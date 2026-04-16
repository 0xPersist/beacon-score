#!/usr/bin/env python3
"""
Generate synthetic Zeek log samples for testing beacon-score.
Produces conn.log, dns.log, ssl.log with a mix of:
  - High-confidence beacon (regular C2)
  - Medium-confidence (noisy beacon)
  - DGA-style DNS
  - Normal browsing traffic (noise)
"""

import json
import math
import random
import time
import os

random.seed(42)
BASE_TS = time.time() - 3600 * 6  # 6 hours ago


def jitter(base: float, pct: float = 0.05) -> float:
    return base + random.uniform(-base * pct, base * pct)


def uid() -> str:
    return "C" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=17))


def write_json_log(path: str, records: list[dict]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"  wrote {len(records):>5} records → {path}")


# ── Beacon profiles ──────────────────────────────────────────────────────────

def gen_high_confidence_beacon(dest_ip: str, interval: float = 60.0, count: int = 180):
    """Regular 60s beacon, tiny uniform payload, self-signed cert."""
    conn, dns, ssl = [], [], []
    ts = BASE_TS
    for _ in range(count):
        ts += jitter(interval, 0.02)  # very low jitter
        orig = random.randint(128, 160)
        resp = random.randint(64, 80)
        conn.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.50",
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dest_ip,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": round(random.uniform(0.1, 0.4), 4),
            "orig_bytes": orig,
            "resp_bytes": resp,
            "conn_state": "SF",
            "orig_pkts": 4,
            "resp_pkts": 3,
        })
        if len(ssl) < 5:
            ssl.append({
                "ts": round(ts, 6),
                "uid": conn[-1]["uid"],
                "id.orig_h": "10.0.0.50",
                "id.resp_h": dest_ip,
                "id.resp_p": 443,
                "version": "TLSv12",
                "server_name": f"updates.{dest_ip}.io",
                "subject": f"CN={dest_ip}",
                "issuer": f"CN={dest_ip}",          # self-signed
                "not_valid_before": "2025-01-15T00:00:00",
                "not_valid_after": "2025-04-15T00:00:00",  # 90 day cert
                "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
                "ja3s": "ec74a5c51106f0419184d0dd08fb05bc",
                "validation_status": "self signed certificate",
            })
    return conn, dns, ssl


def gen_medium_beacon(dest_ip: str, interval: float = 300.0, count: int = 72):
    """5-min beacon with moderate jitter, legit-looking cert."""
    conn, dns, ssl = [], [], []
    ts = BASE_TS
    for i in range(count):
        ts += jitter(interval, 0.15)  # medium jitter
        conn.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.51",
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dest_ip,
            "id.resp_p": 8443,
            "proto": "tcp",
            "service": "ssl",
            "duration": round(random.uniform(1.0, 3.0), 4),
            "orig_bytes": random.randint(200, 350),
            "resp_bytes": random.randint(100, 200),
            "conn_state": "SF",
            "orig_pkts": random.randint(5, 8),
            "resp_pkts": random.randint(4, 7),
        })
        if i == 0:
            ssl.append({
                "ts": round(ts, 6),
                "uid": conn[-1]["uid"],
                "id.orig_h": "10.0.0.51",
                "id.resp_h": dest_ip,
                "id.resp_p": 8443,
                "version": "TLSv13",
                "server_name": "telemetry.example-cdn.com",
                "subject": "CN=*.example-cdn.com,O=ExampleCDN Inc",
                "issuer": "CN=R3,O=Let's Encrypt,C=US",
                "not_valid_before": "2024-09-01T00:00:00",
                "not_valid_after": "2025-09-01T00:00:00",
                "ja3": "b32309a26951912be7dba376398abc3b",
                "validation_status": "ok",
            })
    return conn, dns, ssl


def gen_dga_traffic(dest_ip: str, count: int = 60):
    """High-entropy subdomain DNS queries resolving to a C2 IP."""
    conn, dns, ssl = [], [], []
    ts = BASE_TS
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(count):
        ts += random.uniform(5, 30)
        sub_len = random.randint(12, 22)
        subdomain = "".join(random.choices(alphabet, k=sub_len))
        fqdn = f"{subdomain}.dyndns-update.net"
        u = uid()
        dns.append({
            "ts": round(ts, 6),
            "uid": u,
            "id.orig_h": "10.0.0.52",
            "id.resp_h": "8.8.8.8",
            "query": fqdn,
            "qtype": "A",
            "answers": [dest_ip],
            "TTLs": [30.0],
            "rcode": "NOERROR",
        })
        conn.append({
            "ts": round(ts + 0.1, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.52",
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dest_ip,
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": round(random.uniform(0.05, 0.5), 4),
            "orig_bytes": random.randint(80, 200),
            "resp_bytes": random.randint(40, 120),
            "conn_state": "SF",
            "orig_pkts": 3,
            "resp_pkts": 2,
        })
    return conn, dns, ssl


def gen_normal_traffic(count: int = 400):
    """Simulate normal browsing — irregular intervals, varied destinations."""
    conn, dns, ssl = [], [], []
    normal_dests = [
        "142.250.80.46", "151.101.1.164", "104.16.85.20",
        "172.217.14.228", "13.107.42.14", "199.232.68.133",
    ]
    ts = BASE_TS
    for _ in range(count):
        ts += random.uniform(1, 120)
        dest = random.choice(normal_dests)
        conn.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.100",
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dest,
            "id.resp_p": random.choice([80, 443, 443, 443]),
            "proto": "tcp",
            "service": random.choice(["http", "ssl"]),
            "duration": round(random.uniform(0.2, 15.0), 4),
            "orig_bytes": random.randint(500, 50000),
            "resp_bytes": random.randint(1000, 200000),
            "conn_state": "SF",
            "orig_pkts": random.randint(5, 50),
            "resp_pkts": random.randint(8, 80),
        })
    return conn, dns, ssl


# ── Assemble and write ────────────────────────────────────────────────────────

def generate(output_dir: str = "sample_logs"):
    print(f"\nGenerating synthetic Zeek logs → {output_dir}/\n")

    all_conn, all_dns, all_ssl = [], [], []

    # HIGH confidence beacon: 185.220.101.45
    c, d, s = gen_high_confidence_beacon("185.220.101.45", interval=60, count=180)
    all_conn += c; all_dns += d; all_ssl += s
    print("  [HIGH]   185.220.101.45  60s regular beacon, self-signed cert, 180 sessions")

    # MEDIUM confidence beacon: 194.165.16.11
    c, d, s = gen_medium_beacon("194.165.16.11", interval=300, count=72)
    all_conn += c; all_dns += d; all_ssl += s
    print("  [MEDIUM] 194.165.16.11   5-min beacon, moderate jitter, 72 sessions")

    # DGA traffic: 45.142.212.100
    c, d, s = gen_dga_traffic("45.142.212.100", count=60)
    all_conn += c; all_dns += d; all_ssl += s
    print("  [DGA]    45.142.212.100  high-entropy subdomains, 60 DNS+conn pairs")

    # Normal noise
    c, d, s = gen_normal_traffic(count=400)
    all_conn += c; all_dns += d; all_ssl += s
    print("  [NOISE]  various         normal browsing traffic, 400 sessions\n")

    # Shuffle to simulate real mixed log order
    random.shuffle(all_conn)
    random.shuffle(all_dns)

    write_json_log(f"{output_dir}/conn.log", all_conn)
    write_json_log(f"{output_dir}/dns.log", all_dns)
    write_json_log(f"{output_dir}/ssl.log", all_ssl)

    print(f"\nRun: beacon-score --conn {output_dir}/conn.log --dns {output_dir}/dns.log --ssl {output_dir}/ssl.log --detail\n")


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_logs"
    generate(out)
