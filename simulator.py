#!/usr/bin/env python3
"""
simulator.py — Network Flow & Attack Traffic Simulator for IDS Sentinel.

Generates realistic network flow events (both benign traffic and various attack types
like DDoS, PortScan, DoS, Web Attacks, and Brute Force) and posts them to the
IDS Sentinel backend API for real-time ML detection and alerting.

Usage:
    python simulator.py --url http://localhost:8000 --token YOUR_TOKEN --rate 5
    python simulator.py --token YOUR_TOKEN --attack-type DDoS --count 20
"""

import argparse
import json
import random
import sys
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Traffic profiles
# ---------------------------------------------------------------------------

def generate_benign_flow():
    dst_port = random.choice([80, 443, 53, 8080, 8443, 123])
    flow_duration = random.uniform(10_000, 5_000_000)  # microseconds
    fwd_pkts = random.randint(2, 40)
    bwd_pkts = random.randint(2, 60)
    fwd_len_max = random.uniform(200, 1460)
    fwd_len_mean = random.uniform(50, 600)
    bwd_len_max = random.uniform(500, 1460)

    return {
        "Destination Port": dst_port,
        "Flow Duration": flow_duration,
        "Total Fwd Packets": fwd_pkts,
        "Total Length of Fwd Packets": fwd_pkts * fwd_len_mean,
        "Fwd Packet Length Max": fwd_len_max,
        "Fwd Packet Length Min": random.uniform(0, 64),
        "Fwd Packet Length Mean": fwd_len_mean,
        "Bwd Packet Length Max": bwd_len_max,
        "Bwd Packet Length Min": random.uniform(0, 64),
        "Flow Bytes/s": random.uniform(1000, 500_000),
        "Flow Packets/s": random.uniform(2, 100),
        "Flow IAT Mean": random.uniform(100, 50_000),
        "Flow IAT Std": random.uniform(10, 10_000),
        "Flow IAT Max": random.uniform(500, 100_000),
        "Flow IAT Min": random.uniform(1, 100),
        "Fwd IAT Mean": random.uniform(100, 50_000),
        "Fwd IAT Std": random.uniform(10, 10_000),
        "Fwd IAT Min": random.uniform(1, 100),
        "Bwd IAT Total": random.uniform(1000, 500_000),
        "Bwd IAT Mean": random.uniform(100, 50_000),
        "Bwd IAT Std": random.uniform(10, 10_000),
        "Bwd IAT Max": random.uniform(500, 100_000),
        "Bwd IAT Min": random.uniform(1, 100),
        "Fwd PSH Flags": random.choice([0, 1]),
        "Fwd URG Flags": 0,
        "Fwd Header Length": fwd_pkts * 20,
        "Bwd Header Length": bwd_pkts * 20,
        "Bwd Packets/s": random.uniform(1, 50),
        "Min Packet Length": 0,
        "Max Packet Length": 1460,
        "Packet Length Mean": random.uniform(200, 800),
        "Packet Length Variance": random.uniform(1000, 200_000),
        "FIN Flag Count": random.choice([0, 1]),
        "RST Flag Count": 0,
        "PSH Flag Count": random.choice([0, 1]),
        "ACK Flag Count": 1,
        "URG Flag Count": 0,
        "Down/Up Ratio": random.uniform(0.5, 3.0),
        "Init_Win_bytes_forward": 65535,
        "Init_Win_bytes_backward": 65535,
        "act_data_pkt_fwd": max(1, fwd_pkts - 2),
        "min_seg_size_forward": 20,
        "Active Mean": random.uniform(0, 1000),
        "Active Std": 0,
        "Active Max": random.uniform(0, 1000),
        "Active Min": 0,
        "Idle Std": random.uniform(0, 500),
    }, dst_port, "TCP"


def generate_ddos_flow():
    dst_port = random.choice([80, 443, 8080])
    fwd_pkts = random.randint(200, 5000)
    duration = random.uniform(1000, 80_000)
    return {
        "Destination Port": dst_port,
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_pkts,
        "Total Length of Fwd Packets": fwd_pkts * 1400,
        "Fwd Packet Length Max": 1460,
        "Fwd Packet Length Min": 1000,
        "Fwd Packet Length Mean": 1380,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Flow Bytes/s": random.uniform(10_000_000, 90_000_000),
        "Flow Packets/s": random.uniform(5000, 60_000),
        "Flow IAT Mean": random.uniform(0.5, 20),
        "Flow IAT Std": random.uniform(0.1, 5),
        "Flow IAT Max": random.uniform(10, 100),
        "Flow IAT Min": 0.1,
        "Fwd IAT Mean": random.uniform(0.5, 20),
        "Fwd IAT Std": random.uniform(0.1, 5),
        "Fwd IAT Min": 0.1,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Fwd Header Length": fwd_pkts * 20,
        "Bwd Header Length": 0,
        "Bwd Packets/s": 0,
        "Min Packet Length": 1000,
        "Max Packet Length": 1460,
        "Packet Length Mean": 1380,
        "Packet Length Variance": 250,
        "FIN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 0,
        "URG Flag Count": 0,
        "Down/Up Ratio": 0,
        "Init_Win_bytes_forward": 1024,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": fwd_pkts,
        "min_seg_size_forward": 20,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Std": 0,
    }, dst_port, "TCP"


def generate_portscan_flow(destination_port=None):
    dst_port = destination_port or random.choice(
        [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
    )
    return {
        "Destination Port": dst_port,
        "Flow Duration": random.uniform(10, 500),
        "Total Fwd Packets": 1,
        "Total Length of Fwd Packets": 0,
        "Fwd Packet Length Max": 0,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Flow Bytes/s": 0,
        "Flow Packets/s": random.uniform(2000, 100_000),
        "Flow IAT Mean": 0,
        "Flow IAT Std": 0,
        "Flow IAT Max": 0,
        "Flow IAT Min": 0,
        "Fwd IAT Mean": 0,
        "Fwd IAT Std": 0,
        "Fwd IAT Min": 0,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Fwd Header Length": 20,
        "Bwd Header Length": 0,
        "Bwd Packets/s": 0,
        "Min Packet Length": 0,
        "Max Packet Length": 0,
        "Packet Length Mean": 0,
        "Packet Length Variance": 0,
        "FIN Flag Count": 0,
        "RST Flag Count": 0,
        "SYN Flag Count": 1,
        "PSH Flag Count": 0,
        "ACK Flag Count": 0,
        "URG Flag Count": 0,
        "Down/Up Ratio": 0,
        "Init_Win_bytes_forward": 1024,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": 0,
        "min_seg_size_forward": 20,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Std": 0,
    }, dst_port, "TCP"


def generate_bruteforce_flow():
    dst_port = random.choice([21, 22, 3389])
    fwd_pkts = random.randint(8, 25)
    bwd_pkts = random.randint(6, 20)
    return {
        "Destination Port": dst_port,
        "Flow Duration": random.uniform(150_000, 800_000),
        "Total Fwd Packets": fwd_pkts,
        "Total Length of Fwd Packets": fwd_pkts * 85,
        "Fwd Packet Length Max": 180,
        "Fwd Packet Length Min": 40,
        "Fwd Packet Length Mean": 85,
        "Bwd Packet Length Max": 240,
        "Bwd Packet Length Min": 40,
        "Flow Bytes/s": random.uniform(2000, 15_000),
        "Flow Packets/s": random.uniform(15, 60),
        "Flow IAT Mean": random.uniform(10_000, 50_000),
        "Flow IAT Std": random.uniform(2_000, 15_000),
        "Flow IAT Max": random.uniform(50_000, 120_000),
        "Flow IAT Min": 10,
        "Fwd IAT Mean": random.uniform(15_000, 60_000),
        "Fwd IAT Std": random.uniform(3_000, 20_000),
        "Fwd IAT Min": 10,
        "Bwd IAT Total": random.uniform(100_000, 600_000),
        "Bwd IAT Mean": random.uniform(15_000, 60_000),
        "Bwd IAT Std": random.uniform(3_000, 20_000),
        "Bwd IAT Max": random.uniform(50_000, 150_000),
        "Bwd IAT Min": 10,
        "Fwd PSH Flags": 1,
        "Fwd URG Flags": 0,
        "Fwd Header Length": fwd_pkts * 20,
        "Bwd Header Length": bwd_pkts * 20,
        "Bwd Packets/s": random.uniform(10, 30),
        "Min Packet Length": 40,
        "Max Packet Length": 240,
        "Packet Length Mean": 90,
        "Packet Length Variance": 2500,
        "FIN Flag Count": 1,
        "RST Flag Count": 1,
        "PSH Flag Count": 1,
        "ACK Flag Count": 1,
        "URG Flag Count": 0,
        "Down/Up Ratio": 0.8,
        "Init_Win_bytes_forward": 29200,
        "Init_Win_bytes_backward": 29200,
        "act_data_pkt_fwd": fwd_pkts - 3,
        "min_seg_size_forward": 20,
        "Active Mean": random.uniform(500, 5000),
        "Active Std": 0,
        "Active Max": random.uniform(500, 5000),
        "Active Min": 0,
        "Idle Std": 0,
    }, dst_port, "TCP"


def generate_webattack_flow():
    dst_port = random.choice([80, 443])
    fwd_pkts = random.randint(4, 12)
    bwd_pkts = random.randint(3, 10)
    return {
        "Destination Port": dst_port,
        "Flow Duration": random.uniform(200_000, 2_000_000),
        "Total Fwd Packets": fwd_pkts,
        "Total Length of Fwd Packets": random.uniform(1200, 4500),
        "Fwd Packet Length Max": 1460,
        "Fwd Packet Length Min": 40,
        "Fwd Packet Length Mean": random.uniform(300, 800),
        "Bwd Packet Length Max": 800,
        "Bwd Packet Length Min": 40,
        "Flow Bytes/s": random.uniform(3000, 25_000),
        "Flow Packets/s": random.uniform(5, 30),
        "Flow IAT Mean": random.uniform(20_000, 100_000),
        "Flow IAT Std": random.uniform(5_000, 30_000),
        "Flow IAT Max": random.uniform(100_000, 300_000),
        "Flow IAT Min": 20,
        "Fwd IAT Mean": random.uniform(25_000, 120_000),
        "Fwd IAT Std": random.uniform(5_000, 35_000),
        "Fwd IAT Min": 20,
        "Bwd IAT Total": random.uniform(150_000, 1_500_000),
        "Bwd IAT Mean": random.uniform(25_000, 120_000),
        "Bwd IAT Std": random.uniform(5_000, 35_000),
        "Bwd IAT Max": random.uniform(100_000, 400_000),
        "Bwd IAT Min": 20,
        "Fwd PSH Flags": 1,
        "Fwd URG Flags": 0,
        "Fwd Header Length": fwd_pkts * 20,
        "Bwd Header Length": bwd_pkts * 20,
        "Bwd Packets/s": random.uniform(3, 15),
        "Min Packet Length": 40,
        "Max Packet Length": 1460,
        "Packet Length Mean": random.uniform(250, 600),
        "Packet Length Variance": 45000,
        "FIN Flag Count": 1,
        "RST Flag Count": 0,
        "PSH Flag Count": 1,
        "ACK Flag Count": 1,
        "URG Flag Count": 0,
        "Down/Up Ratio": 0.6,
        "Init_Win_bytes_forward": 65535,
        "Init_Win_bytes_backward": 65535,
        "act_data_pkt_fwd": fwd_pkts - 2,
        "min_seg_size_forward": 20,
        "Active Mean": random.uniform(1000, 10_000),
        "Active Std": 0,
        "Active Max": random.uniform(1000, 10_000),
        "Active Min": 0,
        "Idle Std": random.uniform(100, 1000),
    }, dst_port, "TCP"


# ---------------------------------------------------------------------------
# Main simulator runner
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="IDS Sentinel Traffic & Attack Simulator")
    parser.add_argument("--url", default="http://localhost:8000/api/v1/events", help="Backend events endpoint URL")
    parser.add_argument("--token", required=True, help="Agent authentication token")
    parser.add_argument("--rate", type=float, default=2.0, help="Events per second (default: 2)")
    parser.add_argument("--count", type=int, default=0, help="Total events to send (0 = infinite)")
    parser.add_argument("--attack-ratio", type=float, default=0.35, help="Ratio of attack to benign traffic (default: 0.35)")
    parser.add_argument("--attack-type", choices=["mixed", "DDoS", "PortScan", "BruteForce", "WebAttack"], default="mixed")
    args = parser.parse_args()

    url = args.url
    if not url.endswith("/events"):
        url = url.rstrip("/") + "/api/v1/events"

    print("=" * 65)
    print("[IDS Sentinel] Real-Time Traffic & Attack Simulator")
    print("=" * 65)
    print(f"Target URL:    {url}")
    print(f"Send Rate:     {args.rate} event(s)/sec")
    print(f"Attack Ratio:  {int(args.attack_ratio * 100)}%")
    print(f"Attack Type:   {args.attack_type}")
    print(f"Total Count:   {'Infinite (Press Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 65)

    sent = 0
    errors = 0
    interval = 1.0 / max(0.1, args.rate)

    threat_ips = [
        "198.51.100.23", "203.0.113.195", "192.0.2.77", "185.220.101.5",
        "45.33.32.156", "104.244.42.1", "172.56.21.90"
    ]
    internal_ips = ["192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.105"]
    scan_source_ip = threat_ips[0]
    scan_target_ip = internal_ips[0]
    next_scan_port = 1

    try:
        while True:
            is_attack = random.random() < args.attack_ratio

            if not is_attack:
                label = "BENIGN"
                features, dst_port, proto = generate_benign_flow()
                src_ip = random.choice(internal_ips)
                dst_ip = f"142.250.{random.randint(1, 254)}.{random.randint(1, 254)}"
            else:
                choice = args.attack_type
                if choice == "mixed":
                    choice = random.choice(["DDoS", "PortScan", "BruteForce", "WebAttack"])
                
                label = choice
                if choice == "DDoS":
                    features, dst_port, proto = generate_ddos_flow()
                elif choice == "PortScan":
                    features, dst_port, proto = generate_portscan_flow(next_scan_port)
                    src_ip = scan_source_ip
                    dst_ip = scan_target_ip
                    next_scan_port = 1 if next_scan_port >= 65535 else next_scan_port + 1
                elif choice == "BruteForce":
                    features, dst_port, proto = generate_bruteforce_flow()
                else:
                    features, dst_port, proto = generate_webattack_flow()

                if choice != "PortScan":
                    src_ip = random.choice(threat_ips)
                    dst_ip = random.choice(internal_ips)

            src_port = random.randint(32768, 65535)

            payload = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": proto,
                "features": features,
            }

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {args.token}",
                    "Content-Type": "application/json",
                    "User-Agent": "IDS-Simulator/1.0",
                },
                method="POST",
            )

            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    res_body = json.loads(response.read().decode("utf-8"))
                    prediction = res_body.get("prediction", "UNKNOWN")
                    confidence = res_body.get("confidence", 0.0)
                    severity = res_body.get("severity", "INFO")
                    alert_id = res_body.get("alert_id")
                    now_str = datetime.now().strftime("%H:%M:%S")

                    tag = "[ALERT]" if severity in ("HIGH", "CRITICAL") else ("[WARN]" if severity == "MEDIUM" else "[INFO]")
                    print(f"[{now_str}] {tag:<7} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Class: {prediction:<15} Conf: {confidence:.2f} | Sev: {severity} | Alert: {alert_id or '-'}")
                    sent += 1

            except urllib.error.HTTPError as e:
                err_text = e.read().decode("utf-8", errors="ignore")
                print(f"[ERROR] HTTP {e.code}: {err_text[:160]}")
                errors += 1
            except Exception as e:
                print(f"[ERROR] Network Error: {e}")
                errors += 1

            if args.count > 0 and sent >= args.count:
                print(f"\nDone! Sent {sent} simulated events.")
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\nStopped by user. Total sent: {sent}, Errors: {errors}")


if __name__ == "__main__":
    main()
