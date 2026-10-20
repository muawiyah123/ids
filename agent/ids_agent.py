#!/usr/bin/env python3
"""
ids_agent.py - Real-time network flow feature extraction agent (IDS prototype)

CHANGES vs previous version
-----------------------------
  - Packet lengths use ip.len (IP-layer), NOT len(pkt) (Ethernet frame).
    Scapy Padding layer is also subtracted, so bare ACKs give payload_len=0.
  - IAT, Active and Idle features are in MICROSECONDS (x1e6) matching CICIDS2017.
  - Flow Bytes/s and Flow Packets/s emit math.inf for zero-duration flows,
    matching CICFlowMeter; inf->NaN in the backend sanitizer = training parity.
  - Standard deviation uses sample formula (div n-1), matching CICFlowMeter.
  - Active/idle timeout is 5 s (CICFlowMeter default), not 1 s.
  - Direction set from TCP SYN-without-ACK where possible.
  - Flows end on FIN handshake completion or RST (no 120 s wait needed).
  - Port reuse: ended flow is queued for reporting; fresh flow starts on new SYN.
  - --report-active only snapshots flows with NEW packets since last snapshot.
  - Ctrl+C flushes all remaining flows before exit.
  - MAX_FLOWS=65536 and MAX_PKTS_PER_FLOW=10000 cap memory usage.
  - Self-traffic (agent->backend) is excluded from the flow table.

REQUIREMENTS
------------
    pip install scapy aiohttp

Elevated privileges required for packet capture:
    sudo python3 ids_agent.py --iface eth0 --dry-run
  Windows: run terminal as Administrator + install Npcap (npcap.com)
"""

import argparse
import asyncio
import json
import logging
import math
import os
import statistics
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from scapy.all import sniff, IP, TCP, UDP, Padding

try:
    import aiohttp
except ImportError:
    aiohttp = None

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ids_agent")

FLOW_TIMEOUT          = 120.0  # inactivity timeout (s) before expiry
ACTIVE_IDLE_THRESHOLD = 5.0    # CICFlowMeter activity timeout: gap > 5 s -> idle
BULK_GAP_THRESHOLD    = 1.0    # gap (s) that breaks a bulk run
BULK_MIN_PACKETS      = 4      # min consecutive payload packets for a bulk
MAX_FLOWS             = 65_536 # hard cap - protects against SYN-flood
MAX_PKTS_PER_FLOW     = 10_000 # cap on stored packets per direction

TCP_FLAG_BITS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PktRecord:
    ts:          float
    length:      int          # ip.len (IP-layer total, no Ethernet padding)
    header_len:  int          # TCP/UDP header bytes
    payload_len: int          # ip.len - IP hdr - L4 hdr - Ethernet padding
    flags:       str          # Scapy flag string e.g. "SA"
    win:         Optional[int]  # TCP window; None for UDP


@dataclass
class Flow:
    key:              Tuple
    protocol:         str
    destination_port: int
    forward_addr:     Tuple[str, int]  # (ip, port) of initiator -> defines fwd
    start_time:       float
    last_time:        float = 0.0
    fwd:              List[PktRecord] = field(default_factory=list)
    bwd:              List[PktRecord] = field(default_factory=list)
    init_win_fwd:     Optional[int]   = None
    init_win_bwd:     Optional[int]   = None
    flag_counts:      Dict[str, int]  = field(
        default_factory=lambda: {v: 0 for v in TCP_FLAG_BITS.values()})
    fwd_psh:  int  = 0
    bwd_psh:  int  = 0
    fwd_urg:  int  = 0
    bwd_urg:  int  = 0
    fwd_fin:  bool = False
    bwd_fin:  bool = False
    rst_seen: bool = False
    ended:    bool = False   # True once FIN complete or RST seen
    # Dedup guard for --report-active
    pkts_at_last_report: int = 0


# ---------------------------------------------------------------------------
# Flow table
# ---------------------------------------------------------------------------

class FlowTable:
    def __init__(self, exclude_addrs: Optional[Set[Tuple[str, int]]] = None):
        self._flows:       Dict[Tuple, Flow] = {}
        self._lock         = threading.Lock()
        self._exclude_addrs: Set[Tuple[str, int]] = exclude_addrs or set()
        self._ended_queue: List[Flow] = []

    @staticmethod
    def _flow_key(ip_src, ip_dst, sport, dport, proto):
        endpoints = sorted([(ip_src, sport), (ip_dst, dport)])
        return (endpoints[0], endpoints[1], proto)

    def ingest(self, pkt) -> None:
        if IP not in pkt:
            return
        ip = pkt[IP]

        if TCP in pkt:
            l4 = pkt[TCP]
            proto      = "TCP"
            sport, dport = int(l4.sport), int(l4.dport)
            header_len = int(l4.dataofs) * 4 if l4.dataofs else 20
            flags      = str(l4.flags)
            win        = int(l4.window)
        elif UDP in pkt:
            l4 = pkt[UDP]
            proto      = "UDP"
            sport, dport = int(l4.sport), int(l4.dport)
            header_len = 8
            flags      = ""
            win        = None
        else:
            return

        # Exclude self-traffic (agent <-> backend)
        if (ip.src, sport) in self._exclude_addrs or \
           (ip.dst, dport) in self._exclude_addrs:
            return

        # Packet length: ip.len excludes Ethernet frame padding
        ip_hdr_len = (ip.ihl * 4) if ip.ihl else 20
        total_len  = int(ip.len)
        pad_bytes  = len(pkt[Padding]) if Padding in pkt else 0
        payload_len = max(total_len - ip_hdr_len - header_len - pad_bytes, 0)

        key = self._flow_key(ip.src, ip.dst, sport, dport, proto)
        now = float(pkt.time) if pkt.time else time.time()

        is_syn_only = proto == "TCP" and "S" in flags and "A" not in flags

        with self._lock:
            flow = self._flows.get(key)

            if flow is None:
                if len(self._flows) >= MAX_FLOWS:
                    log.warning("Flow table full (%d); dropping %s", MAX_FLOWS, key)
                    return
                flow = Flow(
                    key=key, protocol=proto,
                    destination_port=dport,
                    forward_addr=(ip.src, sport),
                    start_time=now, last_time=now,
                )
                self._flows[key] = flow
            else:
                if flow.ended:
                    # Port reuse: queue old flow, start fresh
                    self._ended_queue.append(flow)
                    del self._flows[key]
                    if len(self._flows) >= MAX_FLOWS:
                        return
                    flow = Flow(
                        key=key, protocol=proto,
                        destination_port=dport,
                        forward_addr=(ip.src, sport),
                        start_time=now, last_time=now,
                    )
                    self._flows[key] = flow
                elif is_syn_only and (len(flow.fwd) + len(flow.bwd)) <= 3:
                    # Correct direction if we caught a mid-connection start
                    flow.forward_addr    = (ip.src, sport)
                    flow.destination_port = dport

            is_fwd = (ip.src, sport) == flow.forward_addr
            rec = PktRecord(ts=now, length=total_len, header_len=header_len,
                            payload_len=payload_len, flags=flags, win=win)

            if is_fwd:
                if len(flow.fwd) < MAX_PKTS_PER_FLOW:
                    flow.fwd.append(rec)
                if flow.init_win_fwd is None and win is not None:
                    flow.init_win_fwd = win
                if "P" in flags: flow.fwd_psh += 1
                if "U" in flags: flow.fwd_urg += 1
                if "F" in flags: flow.fwd_fin  = True
            else:
                if len(flow.bwd) < MAX_PKTS_PER_FLOW:
                    flow.bwd.append(rec)
                if flow.init_win_bwd is None and win is not None:
                    flow.init_win_bwd = win
                if "P" in flags: flow.bwd_psh += 1
                if "U" in flags: flow.bwd_urg += 1
                if "F" in flags: flow.bwd_fin  = True

            for bit, name in TCP_FLAG_BITS.items():
                if bit in flags:
                    flow.flag_counts[name] += 1

            flow.last_time = now

            # Terminate on RST or completed FIN handshake
            if "R" in flags:
                flow.rst_seen = True
                flow.ended    = True
                self._ended_queue.append(flow)
                del self._flows[key]
            elif flow.fwd_fin and flow.bwd_fin:
                flow.ended = True
                self._ended_queue.append(flow)
                del self._flows[key]

    def pop_reportable_flows(self, force_all: bool = False) -> List[Flow]:
        now = time.time()
        out: List[Flow] = []
        with self._lock:
            out.extend(self._ended_queue)
            self._ended_queue.clear()
            for key in list(self._flows.keys()):
                flow = self._flows[key]
                if (now - flow.last_time) > FLOW_TIMEOUT:
                    out.append(flow)
                    del self._flows[key]
                elif force_all:
                    total = len(flow.fwd) + len(flow.bwd)
                    if total > flow.pkts_at_last_report:
                        flow.pkts_at_last_report = total
                        out.append(flow)
        return out

    def flush_all(self) -> List[Flow]:
        with self._lock:
            flows = list(self._flows.values()) + list(self._ended_queue)
            self._flows.clear()
            self._ended_queue.clear()
        return flows


# ---------------------------------------------------------------------------
# Feature helpers
# ---------------------------------------------------------------------------

def _mean(xs: List[float]) -> float:
    return float(statistics.mean(xs)) if xs else 0.0


def _std(xs: List[float]) -> float:
    """Sample std (n-1), matching CICFlowMeter."""
    return float(statistics.stdev(xs)) if len(xs) > 1 else 0.0


def _iats(timestamps: List[float]) -> List[float]:
    """Inter-arrival times in seconds (caller scales to us)."""
    ts = sorted(timestamps)
    return [b - a for a, b in zip(ts, ts[1:])]


def _active_idle(all_ts: List[float]) -> Dict[str, List[float]]:
    """Active-burst and idle-gap durations in seconds (caller scales to us).
    Uses CICFlowMeter 5-second activity timeout."""
    ts = sorted(all_ts)
    if len(ts) < 2:
        return {"active": [], "idle": []}
    active, idle = [], []
    burst_start = prev = ts[0]
    for t in ts[1:]:
        gap = t - prev
        if gap > ACTIVE_IDLE_THRESHOLD:
            active.append(prev - burst_start)
            idle.append(gap)
            burst_start = t
        prev = t
    active.append(prev - burst_start)
    return {"active": [a for a in active if a > 0], "idle": idle}


def _bulk_stats(pkts: List[PktRecord]) -> Tuple[float, float, float]:
    if not pkts:
        return 0.0, 0.0, 0.0
    ps = sorted(pkts, key=lambda p: p.ts)
    bulks: List[List[PktRecord]] = []
    run: List[PktRecord] = []
    for p in ps:
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
    bpb = [sum(p.payload_len for p in b) for b in bulks]
    ppb = [len(b) for b in bulks]
    dur = [max(b[-1].ts - b[0].ts, 1e-6) for b in bulks]
    return _mean(bpb), _mean(ppb), _mean([bp/d for bp, d in zip(bpb, dur)])


# ---------------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------------

def compute_features(flow: Flow) -> dict:
    fwd_lens = [p.length for p in flow.fwd]
    bwd_lens = [p.length for p in flow.bwd]
    fwd_ts   = [p.ts for p in flow.fwd]
    bwd_ts   = [p.ts for p in flow.bwd]
    all_ts   = fwd_ts + bwd_ts
    all_lens = fwd_lens + bwd_lens

    duration    = max(flow.last_time - flow.start_time, 0.0)
    duration_us = duration * 1_000_000  # CICFlowMeter: Flow Duration in us

    flow_iat = _iats(all_ts)
    fwd_iat  = _iats(fwd_ts)
    bwd_iat  = _iats(bwd_ts)
    total_bytes = sum(all_lens)

    # Zero-duration flows: emit inf (CICFlowMeter behaviour for port-scan probes)
    # Backend sanitizer: inf -> NaN; XGBoost handles NaN natively = training parity.
    if duration > 0:
        flow_bytes_s = total_bytes / duration
        flow_pkts_s  = len(all_lens) / duration
        fwd_pkts_s   = len(fwd_lens) / duration
        bwd_pkts_s   = len(bwd_lens) / duration
    else:
        flow_bytes_s = math.inf
        flow_pkts_s  = math.inf
        fwd_pkts_s   = math.inf if fwd_lens else 0.0
        bwd_pkts_s   = math.inf if bwd_lens else 0.0

    fwd_hdr_total = sum(p.header_len for p in flow.fwd)
    bwd_hdr_total = sum(p.header_len for p in flow.bwd)
    act_data_fwd  = sum(1 for p in flow.fwd if p.payload_len > 0)
    min_seg_fwd   = min((p.header_len for p in flow.fwd), default=0)

    ai       = _active_idle(all_ts)
    fwd_bulk = _bulk_stats(flow.fwd)
    bwd_bulk = _bulk_stats(flow.bwd)

    avg_pkt_size     = _mean(all_lens)
    avg_fwd_seg_size = _mean(fwd_lens)
    avg_bwd_seg_size = _mean(bwd_lens)
    pkt_len_std      = _std(all_lens)
    down_up_ratio    = (len(bwd_lens) / len(fwd_lens)) if fwd_lens else 0.0

    return {
        # --- identity (not model input) ---
        "_flow_key":   str(flow.key),
        "_protocol":   flow.protocol,
        "_start_time": flow.start_time,

        "Destination Port":            flow.destination_port,
        "Flow Duration":               duration_us,
        "Total Fwd Packets":           len(fwd_lens),
        "Total Backward Packets":      len(bwd_lens),
        "Total Length of Fwd Packets": sum(fwd_lens),
        "Total Length of Bwd Packets": sum(bwd_lens),
        "Fwd Packet Length Max":       max(fwd_lens, default=0),
        "Fwd Packet Length Min":       min(fwd_lens, default=0),
        "Fwd Packet Length Mean":      _mean(fwd_lens),
        "Fwd Packet Length Std":       _std(fwd_lens),
        "Bwd Packet Length Max":       max(bwd_lens, default=0),
        "Bwd Packet Length Min":       min(bwd_lens, default=0),
        "Bwd Packet Length Mean":      _mean(bwd_lens),
        "Bwd Packet Length Std":       _std(bwd_lens),
        "Flow Bytes/s":                flow_bytes_s,
        "Flow Packets/s":              flow_pkts_s,
        # IAT features: x1e6 -> microseconds (CICFlowMeter unit)
        "Flow IAT Mean":               _mean(flow_iat) * 1e6,
        "Flow IAT Std":                _std(flow_iat)  * 1e6,
        "Flow IAT Max":                max(flow_iat, default=0) * 1e6,
        "Flow IAT Min":                min(flow_iat, default=0) * 1e6,
        "Fwd IAT Total":               sum(fwd_iat) * 1e6,
        "Fwd IAT Mean":                _mean(fwd_iat) * 1e6,
        "Fwd IAT Std":                 _std(fwd_iat)  * 1e6,
        "Fwd IAT Max":                 max(fwd_iat, default=0) * 1e6,
        "Fwd IAT Min":                 min(fwd_iat, default=0) * 1e6,
        "Bwd IAT Total":               sum(bwd_iat) * 1e6,
        "Bwd IAT Mean":                _mean(bwd_iat) * 1e6,
        "Bwd IAT Std":                 _std(bwd_iat)  * 1e6,
        "Bwd IAT Max":                 max(bwd_iat, default=0) * 1e6,
        "Bwd IAT Min":                 min(bwd_iat, default=0) * 1e6,
        "Fwd PSH Flags":               flow.fwd_psh,
        "Bwd PSH Flags":               flow.bwd_psh,
        "Fwd URG Flags":               flow.fwd_urg,
        "Bwd URG Flags":               flow.bwd_urg,
        "Fwd Header Length":           fwd_hdr_total,
        "Bwd Header Length":           bwd_hdr_total,
        "Fwd Packets/s":               fwd_pkts_s,
        "Bwd Packets/s":               bwd_pkts_s,
        "Min Packet Length":           min(all_lens, default=0),
        "Max Packet Length":           max(all_lens, default=0),
        "Packet Length Mean":          avg_pkt_size,
        "Packet Length Std":           pkt_len_std,
        "Packet Length Variance":      pkt_len_std ** 2,
        "FIN Flag Count":              flow.flag_counts["FIN"],
        "SYN Flag Count":              flow.flag_counts["SYN"],
        "RST Flag Count":              flow.flag_counts["RST"],
        "PSH Flag Count":              flow.flag_counts["PSH"],
        "ACK Flag Count":              flow.flag_counts["ACK"],
        "URG Flag Count":              flow.flag_counts["URG"],
        "CWE Flag Count":              flow.flag_counts["CWR"],  # CICFlowMeter: CWR -> CWE
        "ECE Flag Count":              flow.flag_counts["ECE"],
        "Down/Up Ratio":               down_up_ratio,
        "Average Packet Size":         avg_pkt_size,
        "Avg Fwd Segment Size":        avg_fwd_seg_size,
        "Avg Bwd Segment Size":        avg_bwd_seg_size,
        "Fwd Avg Bytes/Bulk":          fwd_bulk[0],
        "Fwd Avg Packets/Bulk":        fwd_bulk[1],
        "Fwd Avg Bulk Rate":           fwd_bulk[2],
        "Bwd Avg Bytes/Bulk":          bwd_bulk[0],
        "Bwd Avg Packets/Bulk":        bwd_bulk[1],
        "Bwd Avg Bulk Rate":           bwd_bulk[2],
        "Subflow Fwd Packets":         len(fwd_lens),
        "Subflow Fwd Bytes":           sum(fwd_lens),
        "Subflow Bwd Packets":         len(bwd_lens),
        "Subflow Bwd Bytes":           sum(bwd_lens),
        "Init_Win_bytes_forward":      flow.init_win_fwd if flow.init_win_fwd is not None else -1,
        "Init_Win_bytes_backward":     flow.init_win_bwd if flow.init_win_bwd is not None else -1,
        "act_data_pkt_fwd":            act_data_fwd,
        "min_seg_size_forward":        min_seg_fwd,
        # Active/Idle: x1e6 -> microseconds (CICFlowMeter unit)
        "Active Mean":                 _mean(ai["active"]) * 1e6,
        "Active Std":                  _std(ai["active"])  * 1e6,
        "Active Max":                  max(ai["active"], default=0) * 1e6,
        "Active Min":                  min(ai["active"], default=0) * 1e6,
        "Idle Mean":                   _mean(ai["idle"])   * 1e6,
        "Idle Std":                    _std(ai["idle"])    * 1e6,
        "Idle Max":                    max(ai["idle"], default=0) * 1e6,
        "Idle Min":                    min(ai["idle"], default=0) * 1e6,
    }


# ---------------------------------------------------------------------------
# JSON-safe serialisation
# ---------------------------------------------------------------------------

def _sanitize_for_json(record: dict) -> dict:
    """Replace float inf/NaN with None (JSON null).
    Backend _sanitise_value() converts None->NaN; XGBoost handles NaN.
    This matches what the training pipeline saw (Inf->NaN via sanitizer)."""
    return {
        k: (None if isinstance(v, float) and not math.isfinite(v) else v)
        for k, v in record.items()
    }


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------

async def send_record(record: dict, server_url: Optional[str], dry_run_file: str,
                      session, token: Optional[str] = None) -> None:
    clean = _sanitize_for_json(record)

    if server_url and session is not None:
        payload = (
            {"features": clean,
             "destination_port": int(clean.get("Destination Port", 0)),
             "protocol": record.get("_protocol") or "TCP"}
            if "/events" in server_url else clean
        )
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            async with session.post(server_url, json=payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status >= 300:
                    body = await resp.text()
                    log.warning("Server rejected (HTTP %s): %s", resp.status, body[:300])
                else:
                    log.info("Sent flow port=%s HTTP %s",
                             record.get("Destination Port"), resp.status)
        except Exception as exc:
            log.error("POST failed, writing locally: %s", exc)
            _append_jsonl(dry_run_file, clean)
    else:
        log.info("DRY-RUN: dst_port=%s fwd=%s bwd=%s dur_us=%.0f",
                 record.get("Destination Port"),
                 record.get("Total Fwd Packets"),
                 record.get("Total Backward Packets"),
                 record.get("Flow Duration", 0) or 0)
        _append_jsonl(dry_run_file, clean)


def _append_jsonl(path: str, record: dict) -> None:
    with open(path, "a") as fh:
        fh.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

def start_sniffer(iface, flow_table: FlowTable, bpf_filter: str,
                  stop_event: threading.Event) -> None:
    def _handler(pkt):
        try:
            flow_table.ingest(pkt)
        except Exception as exc:
            log.debug("Packet ingest error: %s", exc)

    log.info("Sniffer starting: iface=%s filter=%r", iface or "<default>", bpf_filter)
    sniff(iface=iface, filter=bpf_filter, prn=_handler, store=False,
          stop_filter=lambda _: stop_event.is_set())


# ---------------------------------------------------------------------------
# Async reporter loop
# ---------------------------------------------------------------------------

async def reporter_loop(flow_table: FlowTable, interval: float,
                        server_url: Optional[str], dry_run_file: str,
                        report_active_flows: bool,
                        token: Optional[str] = None) -> None:
    session = None
    if server_url:
        if aiohttp is None:
            raise RuntimeError("aiohttp required for --server-url: pip install aiohttp")
        session = aiohttp.ClientSession()

    async def _flush(flows: List[Flow]) -> None:
        if not flows:
            return
        log.info("Reporting %d flow(s)...", len(flows))
        await asyncio.gather(*[
            asyncio.create_task(send_record(
                compute_features(f), server_url, dry_run_file, session, token=token))
            for f in flows
        ], return_exceptions=True)

    try:
        while True:
            await asyncio.sleep(interval)
            flows = flow_table.pop_reportable_flows(force_all=report_active_flows)
            if not flows:
                log.debug("No flows to report this cycle.")
            else:
                await _flush(flows)

    except asyncio.CancelledError:
        # Ctrl+C: flush all remaining flows before exit
        log.info("Shutdown: flushing remaining flows...")
        await _flush(flow_table.flush_all())
        raise

    finally:
        if session is not None:
            await session.close()


# ---------------------------------------------------------------------------
# Self-traffic exclusion
# ---------------------------------------------------------------------------

def _parse_exclude_addrs(server_url: Optional[str]) -> Set[Tuple[str, int]]:
    if not server_url:
        return set()
    try:
        p = urllib.parse.urlparse(server_url)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
        return {(host, port)}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Real-time IDS flow-feature capture agent")
    parser.add_argument("--iface", default=None,
                        help="Network interface (default: Scapy default)")
    parser.add_argument("--filter", default="tcp or udp",
                        help="BPF capture filter")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="Reporting interval in seconds (default 30)")
    parser.add_argument("--server-url", "--url", dest="server_url", default=None,
                        help="ML backend endpoint, e.g. http://localhost:8000/api/v1/events")
    parser.add_argument("--token", "--api-key", dest="token", default=None,
                        help="Agent API token for Bearer auth")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print+log locally even if --server-url is set")
    parser.add_argument("--out-file", default=None,
                        help="Local JSONL output file (dry-run / fallback)")
    parser.add_argument("--out-dir", default=".",
                        help="Directory for auto-timestamped output file")
    parser.add_argument("--report-active", action="store_true",
                        help="Snapshot still-active flows each cycle "
                             "(deduplicated: only flows with new packets are included)")
    args = parser.parse_args()

    out_file = args.out_file or os.path.join(
        args.out_dir, f"flows_{time.strftime('%Y%m%d_%H%M%S')}.jsonl")

    server_url = None if args.dry_run else args.server_url
    if server_url:
        log.info("Mode: LIVE -> POST to %s every %.0fs", server_url, args.interval)
    else:
        log.info("Mode: DRY-RUN -> logging to %s every %.0fs", out_file, args.interval)

    exclude_addrs = _parse_exclude_addrs(server_url)
    if exclude_addrs:
        log.info("Excluding self-traffic: %s", exclude_addrs)

    flow_table  = FlowTable(exclude_addrs=exclude_addrs)
    stop_event  = threading.Event()

    threading.Thread(
        target=start_sniffer,
        args=(args.iface, flow_table, args.filter, stop_event),
        daemon=True,
    ).start()

    try:
        asyncio.run(reporter_loop(
            flow_table=flow_table, interval=args.interval,
            server_url=server_url, dry_run_file=out_file,
            report_active_flows=args.report_active, token=args.token,
        ))
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt - stopping sniffer...")
        stop_event.set()


if __name__ == "__main__":
    main()
