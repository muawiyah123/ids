#!/usr/bin/env python3
"""
ids_agent.py — Real-time network flow feature extraction agent (IDS prototype)

WHAT THIS DOES
---------------
- Sniffs live traffic with Scapy. Windows automatically selects active capture
  adapters; other systems use Scapy's default interface. An explicit interface
  can still be provided for advanced use.
- Groups packets into bidirectional flows keyed by
  (src_ip, src_port, dst_ip, dst_port, protocol) — normalized so both
  directions of the same conversation map to the same flow.
- Maintains running statistics per flow (packet lengths, inter-arrival
  times, TCP flags, header lengths, window sizes, bulk/active/idle
  behaviour, etc.) matching the CICIDS2017 / CICFlowMeter feature set.
- Every REPORT_INTERVAL seconds (default 30s), asynchronously flushes
  flow feature records:
    * if --server-url is given -> POSTs JSON to that endpoint (async, aiohttp)
    * otherwise -> DRY-RUN mode: prints the record and appends it to a
      local JSONL file, so you can test the agent with no backend at all.

WHY THIS MATTERS FOR YOUR PROJECT
----------------------------------
Your ML model was (presumably) trained on CICIDS2017-style columns, so
the *exact* feature engineering matters. This script computes each
feature from first principles and documents the formula used in a
comment next to it — please sanity-check a handful of flows against your
team's training pipeline (or CICFlowMeter output) before trusting the
alerts, especially the bulk/active/idle features, which have some
implementation-specific edge cases even in the original tool.

REQUIREMENTS
------------
    pip install scapy aiohttp

Sniffing raw packets needs elevated privileges:
    sudo python3 ids_agent.py --dry-run
  (Linux alternative to sudo: grant the interpreter CAP_NET_RAW/CAP_NET_ADMIN
   via `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`)

USAGE
-----
    # Test locally, no server, prints + logs every 30s
    sudo python3 ids_agent.py --dry-run

    # Real deployment, POST to your ML server every 30s
    sudo python3 ids_agent.py --server-url http://localhost:8000/api/v1/events
"""

import argparse
import asyncio
from collections import Counter, deque
import json
import logging
import os
import platform
import socket
import statistics
import threading
import time
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.all import conf, sniff, IP, TCP, UDP, show_interfaces

try:
    import aiohttp
except ImportError:
    aiohttp = None  # only required if --server-url is used

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ids_agent")

FLOW_TIMEOUT = 120.0        # seconds of inactivity before a flow is considered ended
TCP_CLOSE_GRACE = 1.0       # wait briefly after teardown for the final ACK/retransmits
HEARTBEAT_INTERVAL = 30.0
SYN_FLOOD_WINDOW = 5.0       # packet-rate window for the explicit SYN-flood signal
SYN_FLOOD_MIN_PACKETS = 200  # SYNs to one destination port inside the window
SYN_FLOOD_COOLDOWN = 30.0    # avoid generating repeated alerts for the same target
ACTIVE_IDLE_THRESHOLD = 1.0  # CICFlowMeter default: gap > 1s => idle period
BULK_GAP_THRESHOLD = 1.0     # gap between packets to still count as same "bulk"
BULK_MIN_PACKETS = 4         # min packets to qualify as a bulk transfer

TCP_FLAG_BITS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

# --------------------------------------------------------------------------
# Per-packet record kept inside a flow
# --------------------------------------------------------------------------

@dataclass
class PktRecord:
    ts: float
    length: int          # total IP packet length
    header_len: int       # TCP/UDP header length (bytes)
    payload_len: int      # length of data above L4 header
    flags: str            # raw scapy flag string, e.g. "SA"
    win: Optional[int]    # TCP window size, None for UDP


@dataclass
class Flow:
    key: Tuple
    protocol: str
    destination_port: int
    forward_addr: Tuple[str, int]   # (ip, port) of the flow initiator -> defines "fwd"
    start_time: float
    last_time: float = 0.0
    fwd: List[PktRecord] = field(default_factory=list)
    bwd: List[PktRecord] = field(default_factory=list)
    init_win_fwd: Optional[int] = None
    init_win_bwd: Optional[int] = None
    fwd_fin: bool = False
    bwd_fin: bool = False
    reset: bool = False
    closed_at: Optional[float] = None
    flag_counts: Dict[str, int] = field(default_factory=lambda: {v: 0 for v in TCP_FLAG_BITS.values()})
    fwd_psh: int = 0
    bwd_psh: int = 0
    fwd_urg: int = 0
    bwd_urg: int = 0


# --------------------------------------------------------------------------
# Flow table (thread-safe: sniff callback runs on a Scapy sniffer thread,
# the reporter loop runs on the asyncio thread)
# --------------------------------------------------------------------------

class FlowTable:
    def __init__(self):
        self._flows: Dict[Tuple, Flow] = {}
        self._lock = threading.Lock()
        self._captured_packets = 0
        self._syn_samples: Dict[Tuple[str, int], deque] = {}
        self._syn_flood_last_alert: Dict[Tuple[str, int], float] = {}
        self._pending_attack_events: List[dict] = []

    @property
    def captured_packets(self) -> int:
        with self._lock:
            return self._captured_packets

    @staticmethod
    def _flow_key(ip_src, ip_dst, sport, dport, proto):
        # Normalize direction so both directions map to the same flow entry.
        endpoints = sorted([(ip_src, sport), (ip_dst, dport)])
        return (endpoints[0], endpoints[1], proto)

    def ingest(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]

        if TCP in pkt:
            l4 = pkt[TCP]
            proto = "TCP"
            sport, dport = int(l4.sport), int(l4.dport)
            header_len = int(l4.dataofs) * 4 if l4.dataofs else 20
            flags = str(l4.flags)
            win = int(l4.window)
        elif UDP in pkt:
            l4 = pkt[UDP]
            proto = "UDP"
            sport, dport = int(l4.sport), int(l4.dport)
            header_len = 8
            flags = ""
            win = None
        else:
            return  # only TCP/UDP flows are modeled here

        total_len = int(len(pkt))
        payload_len = max(total_len - len(ip) + len(bytes(l4)) - header_len, 0)
        # simpler & robust payload estimate: total len minus IP header minus L4 header
        ip_header_len = ip.ihl * 4 if ip.ihl else 20
        payload_len = max(total_len - ip_header_len - header_len, 0)

        key = self._flow_key(ip.src, ip.dst, sport, dport, proto)
        now = float(pkt.time) if pkt.time else time.time()

        with self._lock:
            self._captured_packets += 1
            flow = self._flows.get(key)
            if flow is None:
                flow = Flow(
                    key=key,
                    protocol=proto,
                    destination_port=dport,
                    forward_addr=(ip.src, sport),
                    start_time=now,
                    last_time=now,
                )
                self._flows[key] = flow

            is_fwd = (ip.src, sport) == flow.forward_addr
            rec = PktRecord(ts=now, length=total_len, header_len=header_len,
                             payload_len=payload_len, flags=flags, win=win)

            if is_fwd:
                flow.fwd.append(rec)
                if flow.init_win_fwd is None and win is not None:
                    flow.init_win_fwd = win
                if "P" in flags:
                    flow.fwd_psh += 1
                if "U" in flags:
                    flow.fwd_urg += 1
            else:
                flow.bwd.append(rec)
                if flow.init_win_bwd is None and win is not None:
                    flow.init_win_bwd = win
                if "P" in flags:
                    flow.bwd_psh += 1
                if "U" in flags:
                    flow.bwd_urg += 1

            if proto == "TCP":
                if "R" in flags:
                    flow.reset = True
                    flow.closed_at = now
                if "F" in flags:
                    if is_fwd:
                        flow.fwd_fin = True
                    else:
                        flow.bwd_fin = True
                    if flow.fwd_fin and flow.bwd_fin and flow.closed_at is None:
                        flow.closed_at = now

            for bit, name in TCP_FLAG_BITS.items():
                if bit in flags:
                    flow.flag_counts[name] += 1

            flow.last_time = now

            # Unlike the per-flow classifier, this rule looks at packet rate
            # across flows. It catches SYN floods whose individual half-open
            # flows would otherwise wait for FLOW_TIMEOUT before reporting.
            if proto == "TCP" and "S" in flags and "A" not in flags:
                self._observe_syn_flood(ip.src, ip.dst, dport, now)

    def _observe_syn_flood(self, source_ip: str, destination_ip: str,
                           destination_port: int, now: float) -> None:
        key = (destination_ip, destination_port)
        samples = self._syn_samples.setdefault(key, deque())
        cutoff = now - SYN_FLOOD_WINDOW
        while samples and samples[0][0] < cutoff:
            samples.popleft()
        samples.append((now, source_ip))

        last_alert = self._syn_flood_last_alert.get(key, 0.0)
        if len(samples) < SYN_FLOOD_MIN_PACKETS or now - last_alert < SYN_FLOOD_COOLDOWN:
            return

        source_counts = Counter(src for _, src in samples)
        top_source = source_counts.most_common(1)[0][0]
        unique_sources = len(source_counts)
        sample_count = len(samples)
        timestamp = time.time()
        self._pending_attack_events.append({
            "_event_id": str(uuid.uuid4()),
            "_start_time": timestamp,
            "_source_ip": top_source,
            "_source_port": 0,
            "_destination_ip": destination_ip,
            "_destination_port": destination_port,
            "_protocol": "TCP",
            "_metadata": {
                "detection_rule": "tcp_syn_flood_rate",
                "window_seconds": SYN_FLOOD_WINDOW,
                "syn_packets": sample_count,
                "unique_sources": unique_sources,
            },
            "Destination Port": destination_port,
            "Flow Duration": SYN_FLOOD_WINDOW * 1_000_000,
            "Total Fwd Packets": sample_count,
            "SYN Flag Count": sample_count,
            "Flow Packets/s": sample_count / SYN_FLOOD_WINDOW,
        })
        self._syn_flood_last_alert[key] = now
        samples.clear()

    def pop_attack_events(self) -> List[dict]:
        with self._lock:
            events = self._pending_attack_events
            self._pending_attack_events = []
            return events

    def pop_reportable_flows(self, force_all: bool = False) -> List[Flow]:
        """Return flows that are either timed out (ended) or, in force_all
        mode, every currently active flow -- and remove the ended ones."""
        now = time.time()
        out = []
        with self._lock:
            for key in list(self._flows.keys()):
                flow = self._flows[key]
                ended = (
                    (now - flow.last_time) > FLOW_TIMEOUT
                    or flow.reset
                    or (flow.closed_at is not None and now - flow.closed_at >= TCP_CLOSE_GRACE)
                )
                if ended:
                    out.append(flow)
                    del self._flows[key]
                elif force_all:
                    out.append(flow)
        return out


# --------------------------------------------------------------------------
# Feature computation (CICIDS2017 / CICFlowMeter-style column set)
# --------------------------------------------------------------------------

def _mean(xs):
    return float(statistics.mean(xs)) if xs else 0.0


def _std(xs):
    return float(statistics.pstdev(xs)) if len(xs) > 1 else 0.0


def _iats(timestamps: List[float]) -> List[float]:
    ts = sorted(timestamps)
    # CICFlowMeter's Flow/Fwd/Bwd IAT features are expressed in microseconds.
    return [(b - a) * 1_000_000 for a, b in zip(ts, ts[1:])]


def _active_idle(all_ts: List[float]) -> Dict[str, List[float]]:
    """Split a sorted timestamp sequence into 'active' burst durations and
    'idle' gap durations using the CICFlowMeter-style threshold approach."""
    ts = sorted(all_ts)
    if len(ts) < 2:
        return {"active": [], "idle": []}

    active_periods, idle_periods = [], []
    burst_start = ts[0]
    prev = ts[0]
    for t in ts[1:]:
        gap = t - prev
        if gap > ACTIVE_IDLE_THRESHOLD:
            active_periods.append((prev - burst_start) * 1_000_000)
            idle_periods.append(gap * 1_000_000)
            burst_start = t
        prev = t
    active_periods.append((prev - burst_start) * 1_000_000)
    return {"active": [a for a in active_periods if a > 0], "idle": idle_periods}


def _bulk_stats(pkts: List[PktRecord]) -> Tuple[float, float, float]:
    """Approximate CICFlowMeter 'bulk' detection: a run of >=4 consecutive
    packets (in one direction) with payload>0 and <1s gaps between them.
    Returns (avg_bytes_per_bulk, avg_packets_per_bulk, avg_bulk_rate_Bps)."""
    if not pkts:
        return 0.0, 0.0, 0.0
    pkts_sorted = sorted(pkts, key=lambda p: p.ts)
    bulks = []
    run = []
    for p in pkts_sorted:
        if p.payload_len <= 0:
            if len(run) >= BULK_MIN_PACKETS:
                bulks.append(run)
            run = []
            continue
        if run and (p.ts - run[-1].ts) > BULK_GAP_THRESHOLD:
            if len(run) >= BULK_MIN_PACKETS:
                bulks.append(run)
            run = []
        run.append(p)
    if len(run) >= BULK_MIN_PACKETS:
        bulks.append(run)

    if not bulks:
        return 0.0, 0.0, 0.0

    bytes_per_bulk = [sum(p.payload_len for p in b) for b in bulks]
    pkts_per_bulk = [len(b) for b in bulks]
    durations = [max(b[-1].ts - b[0].ts, 1e-6) for b in bulks]
    rates = [bp / d for bp, d in zip(bytes_per_bulk, durations)]

    return _mean(bytes_per_bulk), _mean(pkts_per_bulk), _mean(rates)


def compute_features(flow: Flow) -> dict:
    # CICFlowMeter's packet length statistics and byte counters use the
    # network-layer payload length, not the captured Ethernet/IP frame size.
    fwd_lens = [p.payload_len for p in flow.fwd]
    bwd_lens = [p.payload_len for p in flow.bwd]
    fwd_ts = [p.ts for p in flow.fwd]
    bwd_ts = [p.ts for p in flow.bwd]
    all_ts = fwd_ts + bwd_ts
    all_lens = fwd_lens + bwd_lens

    duration = max(flow.last_time - flow.start_time, 0.0)
    duration_us = duration * 1_000_000  # CICFlowMeter reports Flow Duration in microseconds

    flow_iat = _iats(all_ts)
    fwd_iat = _iats(fwd_ts)
    bwd_iat = _iats(bwd_ts)

    total_bytes = sum(all_lens)
    flow_bytes_s = total_bytes / duration if duration > 0 else 0.0
    flow_pkts_s = len(all_lens) / duration if duration > 0 else 0.0
    fwd_pkts_s = len(fwd_lens) / duration if duration > 0 else 0.0
    bwd_pkts_s = len(bwd_lens) / duration if duration > 0 else 0.0

    fwd_header_total = sum(p.header_len for p in flow.fwd)
    bwd_header_total = sum(p.header_len for p in flow.bwd)

    act_data_pkt_fwd = sum(1 for p in flow.fwd if p.payload_len > 0)
    min_seg_size_fwd = min((p.header_len for p in flow.fwd), default=0)

    act_idle = _active_idle(all_ts)

    fwd_bulk = _bulk_stats(flow.fwd)
    bwd_bulk = _bulk_stats(flow.bwd)

    avg_pkt_size = _mean(all_lens)
    avg_fwd_seg_size = _mean(fwd_lens)
    avg_bwd_seg_size = _mean(bwd_lens)

    down_up_ratio = (len(bwd_lens) / len(fwd_lens)) if fwd_lens else 0.0

    features = {
        # -- flow identity (not model input, useful for correlating alerts) --
        "_flow_key": str(flow.key),
        "_protocol": flow.protocol,
        "_start_time": flow.start_time,
        "_event_id": str(uuid.uuid4()),
        "_source_ip": flow.forward_addr[0],
        "_source_port": flow.forward_addr[1],
        "_destination_ip": (flow.key[1] if flow.forward_addr == flow.key[0] else flow.key[0])[0],
        "_destination_port": (flow.key[1] if flow.forward_addr == flow.key[0] else flow.key[0])[1],

        "Destination Port": flow.destination_port,
        "Flow Duration": duration_us,
        "Total Fwd Packets": len(fwd_lens),
        "Total Backward Packets": len(bwd_lens),
        "Total Length of Fwd Packets": sum(fwd_lens),
        "Total Length of Bwd Packets": sum(bwd_lens),
        "Fwd Packet Length Max": max(fwd_lens, default=0),
        "Fwd Packet Length Min": min(fwd_lens, default=0),
        "Fwd Packet Length Mean": _mean(fwd_lens),
        "Fwd Packet Length Std": _std(fwd_lens),
        "Bwd Packet Length Max": max(bwd_lens, default=0),
        "Bwd Packet Length Min": min(bwd_lens, default=0),
        "Bwd Packet Length Mean": _mean(bwd_lens),
        "Bwd Packet Length Std": _std(bwd_lens),
        "Flow Bytes/s": flow_bytes_s,
        "Flow Packets/s": flow_pkts_s,
        "Flow IAT Mean": _mean(flow_iat),
        "Flow IAT Std": _std(flow_iat),
        "Flow IAT Max": max(flow_iat, default=0),
        "Flow IAT Min": min(flow_iat, default=0),
        "Fwd IAT Total": sum(fwd_iat),
        "Fwd IAT Mean": _mean(fwd_iat),
        "Fwd IAT Std": _std(fwd_iat),
        "Fwd IAT Max": max(fwd_iat, default=0),
        "Fwd IAT Min": min(fwd_iat, default=0),
        "Bwd IAT Total": sum(bwd_iat),
        "Bwd IAT Mean": _mean(bwd_iat),
        "Bwd IAT Std": _std(bwd_iat),
        "Bwd IAT Max": max(bwd_iat, default=0),
        "Bwd IAT Min": min(bwd_iat, default=0),
        "Fwd PSH Flags": flow.fwd_psh,
        "Bwd PSH Flags": flow.bwd_psh,
        "Fwd URG Flags": flow.fwd_urg,
        "Bwd URG Flags": flow.bwd_urg,
        "Fwd Header Length": fwd_header_total,
        "Bwd Header Length": bwd_header_total,
        "Fwd Packets/s": fwd_pkts_s,
        "Bwd Packets/s": bwd_pkts_s,
        "Min Packet Length": min(all_lens, default=0),
        "Max Packet Length": max(all_lens, default=0),
        "Packet Length Mean": avg_pkt_size,
        "Packet Length Std": _std(all_lens),
        "Packet Length Variance": _std(all_lens) ** 2,
        "FIN Flag Count": flow.flag_counts["FIN"],
        "SYN Flag Count": flow.flag_counts["SYN"],
        "RST Flag Count": flow.flag_counts["RST"],
        "PSH Flag Count": flow.flag_counts["PSH"],
        "ACK Flag Count": flow.flag_counts["ACK"],
        "URG Flag Count": flow.flag_counts["URG"],
        "CWE Flag Count": flow.flag_counts["CWR"],  # CICFlowMeter labels CWR as "CWE Flag Count"
        "ECE Flag Count": flow.flag_counts["ECE"],
        "Down/Up Ratio": down_up_ratio,
        "Average Packet Size": avg_pkt_size,
        "Avg Fwd Segment Size": avg_fwd_seg_size,
        "Avg Bwd Segment Size": avg_bwd_seg_size,
        "Fwd Avg Bytes/Bulk": fwd_bulk[0],
        "Fwd Avg Packets/Bulk": fwd_bulk[1],
        "Fwd Avg Bulk Rate": fwd_bulk[2],
        "Bwd Avg Bytes/Bulk": bwd_bulk[0],
        "Bwd Avg Packets/Bulk": bwd_bulk[1],
        "Bwd Avg Bulk Rate": bwd_bulk[2],
        "Subflow Fwd Packets": len(fwd_lens),
        "Subflow Fwd Bytes": sum(fwd_lens),
        "Subflow Bwd Packets": len(bwd_lens),
        "Subflow Bwd Bytes": sum(bwd_lens),
        "Init_Win_bytes_forward": flow.init_win_fwd if flow.init_win_fwd is not None else -1,
        "Init_Win_bytes_backward": flow.init_win_bwd if flow.init_win_bwd is not None else -1,
        "act_data_pkt_fwd": act_data_pkt_fwd,
        "min_seg_size_forward": min_seg_size_fwd,
        "Active Mean": _mean(act_idle["active"]),
        "Active Std": _std(act_idle["active"]),
        "Active Max": max(act_idle["active"], default=0),
        "Active Min": min(act_idle["active"], default=0),
        "Idle Mean": _mean(act_idle["idle"]),
        "Idle Std": _std(act_idle["idle"]),
        "Idle Max": max(act_idle["idle"], default=0),
        "Idle Min": min(act_idle["idle"], default=0),
    }
    return features


# --------------------------------------------------------------------------
# Sender (async, non-blocking) — dry-run local sink or real HTTP POST
# --------------------------------------------------------------------------

async def send_record(record: dict, server_url: Optional[str], dry_run_file: str,
                       session: Optional["aiohttp.ClientSession"], token: Optional[str] = None):
    if server_url and session is not None:
        # If posting to backend events API, format into AgentEvent schema
        if "/events" in server_url:
            payload = {
                "event_id": record.get("_event_id"),
                "timestamp": datetime.fromtimestamp(record["_start_time"], timezone.utc).isoformat()
                    if record.get("_start_time") else None,
                "source_ip": record.get("_source_ip"),
                "source_port": record.get("_source_port"),
                "destination_ip": record.get("_destination_ip"),
                "features": record,
                "destination_port": int(record.get("_destination_port", record.get("Destination Port", 0))),
                "protocol": record.get("_protocol"),
            }
            if record.get("_metadata"):
                payload["metadata"] = record["_metadata"]
        else:
            payload = record

        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            async with session.post(server_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                body = await resp.text()
                accepted = resp.status < 300
                response_data = {}
                if accepted and "/events" in server_url:
                    try:
                        response_data = json.loads(body)
                        accepted = response_data.get("status") in ("accepted", "duplicate")
                    except (json.JSONDecodeError, AttributeError):
                        accepted = False
                if not accepted:
                    log.warning("Server rejected record (HTTP %s): %s", resp.status, body[:300])
                    _append_jsonl(dry_run_file, record)
                else:
                    prediction = response_data.get("prediction")
                    alert_id = response_data.get("alert_id")
                    if prediction:
                        log.info("Sent flow on port %s -> %s (confidence %.1f%%, alert=%s)",
                                 record.get("Destination Port"), prediction,
                                 100 * float(response_data.get("confidence", 0)),
                                 alert_id or "none")
                    else:
                        log.info("Sent flow on port %s -> HTTP %s (%s)",
                                 record.get("Destination Port"), resp.status,
                                 response_data.get("status", "accepted"))
        except Exception as e:
            log.error("Failed to send record to server, falling back to local log: %s", e)
            _append_jsonl(dry_run_file, record)
    else:
        # Dry-run / test mode: no server configured
        log.info("DRY-RUN flow record: dst_port=%s fwd_pkts=%s bwd_pkts=%s duration_us=%.0f",
                  record.get("Destination Port"), record.get("Total Fwd Packets"),
                  record.get("Total Backward Packets"), record.get("Flow Duration"))
        _append_jsonl(dry_run_file, record)


def _append_jsonl(path: str, record: dict):
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


# --------------------------------------------------------------------------
# Sniffer thread
# --------------------------------------------------------------------------

def _get_auto_capture_interfaces():
    """Capture on useful active adapters automatically on Windows.

    Windows hosts often have several virtual and physical adapters. Capture on
    each active non-loopback adapter so users do not need to identify a
    particular adapter before starting the agent.
    """
    if platform.system() != "Windows":
        return None

    ignored_terms = ("loopback", "wan miniport", "bluetooth", "wi-fi direct")
    selected = []
    seen_networks = set()
    try:
        for device in conf.ifaces.values():
            label = " ".join((
                str(getattr(device, "name", "")),
                str(getattr(device, "description", "")),
            )).lower()
            if any(term in label for term in ignored_terms):
                continue
            try:
                if not device.is_valid():
                    continue
            except Exception:
                continue

            network_name = getattr(device, "network_name", None)
            if not network_name or network_name in seen_networks:
                continue
            seen_networks.add(network_name)
            selected.append(device)
    except Exception as exc:
        log.warning("Could not list capture adapters for automatic selection: %s", exc)
        return None

    return selected or None


def start_sniffer(iface: Optional[str], flow_table: FlowTable, bpf_filter: str, stop_event: threading.Event):
    def _handler(pkt):
        try:
            flow_table.ingest(pkt)
        except Exception as e:
            log.debug("Packet ingest error: %s", e)

    def _stop_filter(pkt):
        return stop_event.is_set()

    selected_iface = iface
    if not iface or iface.lower() == "auto":
        selected_iface = _get_auto_capture_interfaces()
        if selected_iface:
            names = [getattr(item, "description", None) or getattr(item, "name", str(item))
                     for item in selected_iface]
            log.info("Automatically capturing on %d active network adapter(s): %s",
                     len(names), ", ".join(names))
        else:
            log.info("Using the operating system's default network adapter")

    log.info("Starting packet capture filter=%r", bpf_filter)
    try:
        sniff(iface=selected_iface, filter=bpf_filter, prn=_handler, store=False, stop_filter=_stop_filter)
    except Exception:
        log.exception("Packet capture stopped because the sniffer failed")
        stop_event.set()


# --------------------------------------------------------------------------
# Async reporter loop
# --------------------------------------------------------------------------

async def heartbeat_loop(session, heartbeat_url: str, token: Optional[str],
                        stop_event: Optional[threading.Event]):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    while not stop_event or not stop_event.is_set():
        try:
            async with session.post(
                heartbeat_url,
                json={"version": "1.0.0", "hostname": socket.gethostname(),
                      "os_info": platform.platform()},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status >= 300:
                    log.warning("Heartbeat rejected (HTTP %s): %s", response.status,
                                (await response.text())[:300])
        except Exception as exc:
            log.warning("Heartbeat failed: %s", exc)

        # Keep the heartbeat cadence independent from the flow flush interval.
        for _ in range(int(HEARTBEAT_INTERVAL)):
            if stop_event and stop_event.is_set():
                return
            await asyncio.sleep(1)

async def reporter_loop(flow_table: FlowTable, interval: float, server_url: Optional[str],
                         dry_run_file: str, report_active_flows: bool, token: Optional[str] = None,
                         heartbeat_url: Optional[str] = None,
                         stop_event: Optional[threading.Event] = None):
    session = None
    if server_url:
        if aiohttp is None:
            raise RuntimeError("aiohttp is required for --server-url mode: pip install aiohttp")
        session = aiohttp.ClientSession()
    heartbeat_task = None
    if heartbeat_url and session is not None:
        heartbeat_task = asyncio.create_task(
            heartbeat_loop(session, heartbeat_url, token, stop_event)
        )

    previous_capture_count = 0
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            await asyncio.sleep(interval)
            if stop_event and stop_event.is_set():
                break
            capture_count = flow_table.captured_packets
            captured_this_interval = capture_count - previous_capture_count
            previous_capture_count = capture_count
            flows = flow_table.pop_reportable_flows(force_all=report_active_flows)
            attack_events = flow_table.pop_attack_events()
            if not flows and not attack_events:
                if captured_this_interval:
                    log.info("Captured %d TCP/UDP packet(s); no completed flows to report yet.",
                             captured_this_interval)
                else:
                    log.warning("Captured no TCP/UDP packets on the selected interface; "
                                "verify it can see the traffic being tested.")
                continue
            log.info("Captured %d TCP/UDP packet(s); reporting %d flow(s) and %d rate alert(s)...",
                     captured_this_interval, len(flows), len(attack_events))
            tasks = []
            records = [compute_features(flow) for flow in flows] + attack_events
            for record in records:
                tasks.append(asyncio.create_task(send_record(record, server_url, dry_run_file, session, token=token)))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if heartbeat_task is not None:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)
        if session is not None:
            await session.close()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Real-time IDS flow-feature capture agent")
    parser.add_argument("--iface", default="auto", help="Capture interface (default: automatically select active adapters)")
    parser.add_argument("--filter", default="tcp or udp", help="BPF capture filter")
    parser.add_argument("--interval", type=float, default=30.0, help="Reporting interval in seconds (default 30)")
    parser.add_argument("--server-url", "--url", dest="server_url", default=None, help="ML server ingest endpoint, e.g. http://localhost:8000/api/v1/events")
    parser.add_argument("--token", "--api-key", dest="token", default=None, help="Agent API token for authentication")
    parser.add_argument("--agent-id", default=None, help="Registered agent ID (enables heartbeat status)")
    parser.add_argument("--dry-run", action="store_true", help="Force dry-run mode even if --server-url is set")
    parser.add_argument("--out-file", default=None,
                         help="Local JSONL log file for dry-run / fallback. If omitted, a fresh "
                              "timestamped file (flows_YYYYMMDD_HHMMSS.jsonl) is created automatically "
                              "for every run, so each session gets its own report.")
    parser.add_argument("--out-dir", default=".",
                         help="Directory the auto-timestamped file is created in (ignored if --out-file is set). "
                              "Must already exist. Default: current directory.")
    parser.add_argument("--report-active", action="store_true",
                         help="Also report still-active (not yet timed out) flows every cycle, "
                              "not just flows that ended. Useful for fast testing.")
    parser.add_argument("--list-ifaces", action="store_true",
                         help="List Scapy-visible capture interfaces and exit")
    args = parser.parse_args()

    if args.list_ifaces:
        show_interfaces()
        return

    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    if args.server_url and not args.dry_run and not args.token:
        parser.error("--token is required when --server-url is set")
    if args.agent_id and not args.server_url:
        parser.error("--agent-id requires --server-url")

    if args.out_file:
        out_file = args.out_file
    else:
        run_timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(args.out_dir, f"flows_{run_timestamp}.jsonl")

    server_url = None if args.dry_run else args.server_url
    if server_url:
        server_url = server_url.rstrip("/")
        if server_url.endswith("/api/v1"):
            server_url += "/events"
        elif not server_url.endswith("/events"):
            server_url += "/api/v1/events"
    heartbeat_url = None
    if server_url and args.agent_id:
        api_root = server_url.rsplit("/events", 1)[0]
        heartbeat_url = f"{api_root}/agents/{args.agent_id}/heartbeat"
    if server_url:
        log.info("Mode: LIVE -> POSTing flow records to %s every %.0fs", server_url, args.interval)
        log.info("(Failed sends also fall back to local file: %s)", out_file)
    else:
        log.info("Mode: DRY-RUN -> printing + logging flow records to %s every %.0fs", out_file, args.interval)

    flow_table = FlowTable()
    stop_event = threading.Event()

    sniff_thread = threading.Thread(
        target=start_sniffer,
        args=(args.iface, flow_table, args.filter, stop_event),
        daemon=True,
    )
    sniff_thread.start()

    try:
        asyncio.run(reporter_loop(
            flow_table=flow_table,
            interval=args.interval,
            server_url=server_url,
            dry_run_file=out_file,
            report_active_flows=args.report_active,
            token=args.token,
            heartbeat_url=heartbeat_url,
            stop_event=stop_event,
        ))
    except KeyboardInterrupt:
        log.info("Shutting down...")
        stop_event.set()


if __name__ == "__main__":
    main()
