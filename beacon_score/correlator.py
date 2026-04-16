"""
Correlates conn.log, dns.log, and ssl.log records by destination IP.
Builds per-destination session bundles and passes them to the scoring engine.
"""

from collections import defaultdict
from .engine import BeaconCandidate, DEFAULT_WEIGHTS, score_candidate
from .parsers import load_conn_log, load_dns_log, load_ssl_log


# Ports and destinations to always exclude from beacon analysis
EXCLUDE_PORTS = {53, 67, 68, 123, 5353}
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "::1", "fe80")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def correlate_and_score(
    conn_path: str,
    dns_path: str,
    ssl_path: str,
    weights: dict = None,
    min_sessions: int = 5,
    exclude_private: bool = True,
    top_n: int = 20,
) -> list[BeaconCandidate]:
    """
    Load logs, correlate per destination, score each candidate.
    Returns list sorted by total_score descending.
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    conn_records = load_conn_log(conn_path) if conn_path else []
    dns_records = load_dns_log(dns_path) if dns_path else []
    ssl_records = load_ssl_log(ssl_path) if ssl_path else []

    # Index DNS and SSL by destination IP
    dns_by_dest: dict[str, list] = defaultdict(list)
    for r in dns_records:
        dest = r.get("id.resp_h", "")
        if dest:
            dns_by_dest[dest].append(r)

    # Also index DNS by resolved IPs in answers field
    dns_by_answer_ip: dict[str, list] = defaultdict(list)
    for r in dns_records:
        answers = r.get("answers", [])
        if isinstance(answers, list):
            for a in answers:
                if isinstance(a, str) and "." in a:
                    dns_by_answer_ip[a].append(r)

    ssl_by_dest: dict[str, list] = defaultdict(list)
    for r in ssl_records:
        dest = r.get("id.resp_h", "")
        if dest:
            ssl_by_dest[dest].append(r)

    # Group conn records by destination IP
    conn_by_dest: dict[str, list] = defaultdict(list)
    for r in conn_records:
        dest = r.get("id.resp_h", "")
        port = r.get("id.resp_p", 0)
        if not dest:
            continue
        if port in EXCLUDE_PORTS:
            continue
        if exclude_private and _is_private(dest):
            continue
        conn_by_dest[dest].append(r)

    candidates = []
    for dest, sessions in conn_by_dest.items():
        if len(sessions) < min_sessions:
            continue

        dns_data = dns_by_dest.get(dest, []) + dns_by_answer_ip.get(dest, [])
        ssl_data = ssl_by_dest.get(dest, [])

        candidate = score_candidate(
            destination=dest,
            conn_sessions=sessions,
            dns_queries=dns_data,
            ssl_sessions=ssl_data,
            weights=weights,
        )
        candidates.append(candidate)

    candidates.sort(key=lambda c: c.total_score, reverse=True)
    return candidates[:top_n]
