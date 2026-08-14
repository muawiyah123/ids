#!/usr/bin/env python3
"""
ids_agent.py — Real-time network flow feature extraction agent (IDS prototype)

WHAT THIS DOES
---------------
- Sniffs live traffic on a chosen interface (Scapy).
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
    sudo python3 ids_agent.py --iface eth0 --dry-run
  (Linux alternative to sudo: grant the interpreter CAP_NET_RAW/CAP_NET_ADMIN
   via `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`)

USAGE
-----
    # Test locally, no server, prints + logs every 30s
    sudo python3 ids_agent.py --iface eth0 --dry-run

    # Real deployment, POST to your ML server every 30s
    sudo python3 ids_agent.py --iface eth0 --server-url http://localhost:8000/ingest
"""

import argparse
import asyncio
import json
import logging
import os
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.all import sniff, IP, TCP, UDP

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

            for bit, name in TCP_FLAG_BITS.items():
                if bit in flags:
                    flow.flag_counts[name] += 1

            flow.last_time = now

    def pop_reportable_flows(self, force_all: bool = False) -> List[Flow]:
        """Return flows that are either timed out (ended) or, in force_all
        mode, every currently active flow -- and remove the ended ones."""
        now = time.time()
        out = []
        with self._lock:
            for key in list(self._flows.keys()):
                flow = self._flows[key]
                ended = (now - flow.last_time) > FLOW_TIMEOUT
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
    return [b - a for a, b in zip(ts, ts[1:])]


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
            active_periods.append(prev - burst_start)
            idle_periods.append(gap)
            burst_start = t
        prev = t
    active_periods.append(prev - burst_start)
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
    fwd_lens = [p.length for p in flow.fwd]
    bwd_lens = [p.length for p in flow.bwd]
    fwd_payload = [p.payload_len for p in flow.fwd]
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
                       session: Optional["aiohttp.ClientSession"]):
    if server_url and session is not None:
        try:
            async with session.post(server_url, json=record, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status >= 300:
                    body = await resp.text()
                    log.warning("Server rejected record (HTTP %s): %s", resp.status, body[:300])
                else:
                    log.info("Sent flow on port %s -> HTTP %s", record.get("Destination Port"), resp.status)
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

def start_sniffer(iface: Optional[str], flow_table: FlowTable, bpf_filter: str, stop_event: threading.Event):
    def _handler(pkt):
        try:
            flow_table.ingest(pkt)
        except Exception as e:
            log.debug("Packet ingest error: %s", e)

    def _stop_filter(pkt):
        return stop_event.is_set()

    log.info("Starting sniffer on iface=%s filter=%r", iface or "default", bpf_filter)
    sniff(iface=iface, filter=bpf_filter, prn=_handler, store=False, stop_filter=_stop_filter)


# --------------------------------------------------------------------------
# Async reporter loop
# --------------------------------------------------------------------------

async def reporter_loop(flow_table: FlowTable, interval: float, server_url: Optional[str],
                         dry_run_file: str, report_active_flows: bool):
    session = None
    if server_url:
        if aiohttp is None:
            raise RuntimeError("aiohttp is required for --server-url mode: pip install aiohttp")
        session = aiohttp.ClientSession()

    try:
        while True:
            await asyncio.sleep(interval)
            flows = flow_table.pop_reportable_flows(force_all=report_active_flows)
            if not flows:
                log.debug("No flows to report this cycle.")
                continue
            log.info("Reporting %d flow(s)...", len(flows))
            tasks = []
            for flow in flows:
                record = compute_features(flow)
                tasks.append(asyncio.create_task(send_record(record, server_url, dry_run_file, session)))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if session is not None:
            await session.close()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Real-time IDS flow-feature capture agent")
    parser.add_argument("--iface", default=None, help="Network interface to sniff on (default: scapy default)")
    parser.add_argument("--filter", default="tcp or udp", help="BPF capture filter")
    parser.add_argument("--interval", type=float, default=30.0, help="Reporting interval in seconds (default 30)")
    parser.add_argument("--server-url", default=None, help="ML server ingest endpoint, e.g. http://localhost:8000/ingest")
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
    args = parser.parse_args()

    if args.out_file:
        out_file = args.out_file
    else:
        run_timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(args.out_dir, f"flows_{run_timestamp}.jsonl")

    server_url = None if args.dry_run else args.server_url
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
        ))
    except KeyboardInterrupt:
        log.info("Shutting down...")
        stop_event.set()


if __name__ == "__main__":
    main()
