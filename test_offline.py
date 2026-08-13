#!/usr/bin/env python3
"""
test_offline.py — Exercise ids_agent's flow tracking + feature extraction
WITHOUT needing root privileges, live traffic, or a server.

It builds synthetic TCP packets with Scapy, feeds them straight into the
same FlowTable.ingest() the real sniffer uses, then computes and prints
the feature record exactly like the real 30s reporter loop would.

Run:
    python3 test_offline.py
"""

import time
import asyncio
from scapy.all import IP, TCP

from ids_agent import FlowTable, compute_features, send_record


def make_pkt(src, sport, dst, dport, flags, length_payload, t):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, window=65535)
    if length_payload:
        pkt = pkt / ("X" * length_payload)
    pkt.time = t  # backdate/forward-date the packet like a real capture timestamp
    return pkt


def simulate_flow(flow_table: FlowTable):
    """Simulate a short HTTP-like exchange: SYN, SYN-ACK, ACK, some data both
    ways, then FIN. Client=10.0.0.5:51000 -> Server=93.184.216.34:443."""
    t0 = time.time()
    client = ("10.0.0.5", 51000)
    server = ("93.184.216.34", 443)

    packets = [
        make_pkt(*client, *server, "S", 0, t0 + 0.000),
        make_pkt(*server, *client, "SA", 0, t0 + 0.010),
        make_pkt(*client, *server, "A", 0, t0 + 0.020),
        make_pkt(*client, *server, "PA", 300, t0 + 0.025),   # request
        make_pkt(*server, *client, "A", 0, t0 + 0.080),
        make_pkt(*server, *client, "PA", 1400, t0 + 0.085),  # response chunk 1
        make_pkt(*server, *client, "PA", 1400, t0 + 0.090),  # response chunk 2 (bulk)
        make_pkt(*server, *client, "PA", 1400, t0 + 0.095),  # response chunk 3
        make_pkt(*server, *client, "PA", 800, t0 + 0.100),   # response chunk 4
        make_pkt(*client, *server, "A", 0, t0 + 0.150),
        make_pkt(*client, *server, "FA", 0, t0 + 0.200),
        make_pkt(*server, *client, "FA", 0, t0 + 0.205),
        make_pkt(*client, *server, "A", 0, t0 + 0.210),
    ]
    for p in packets:
        flow_table.ingest(p)

    return t0


async def main():
    flow_table = FlowTable()
    simulate_flow(flow_table)

    # Force-report the (still "active", since we never wait for the real
    # 120s timeout) flow, just like --report-active would in a live run.
    flows = flow_table.pop_reportable_flows(force_all=True)
    assert len(flows) == 1, f"expected 1 flow, got {len(flows)}"

    record = compute_features(flows[0])

    print("\n=== Computed flow feature record ===")
    for k, v in record.items():
        print(f"{k:30s}: {v}")

    # Exercise the same async send path the real agent uses (dry-run: no server)
    await send_record(record, server_url=None, dry_run_file="test_flows_log.jsonl", session=None)
    print("\nOK: record was also appended to test_flows_log.jsonl (dry-run sink).")

    # A couple of sanity checks so a broken feature calc fails loudly
    assert record["Total Fwd Packets"] == 6, record["Total Fwd Packets"]
    assert record["Total Backward Packets"] == 7, record["Total Backward Packets"]
    assert record["Destination Port"] == 443
    assert record["SYN Flag Count"] == 2
    assert record["FIN Flag Count"] == 2
    assert record["Fwd Avg Bytes/Bulk"] == 0.0  # client never sent 4+ consecutive data pkts
    assert record["Bwd Avg Packets/Bulk"] >= 4   # server's 4 back-to-back response chunks
    print("\nAll sanity checks passed. Agent logic is working correctly.")


if __name__ == "__main__":
    asyncio.run(main())
