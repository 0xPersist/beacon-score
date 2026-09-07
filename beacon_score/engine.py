"""
beacon-score: Multi-signal C2 beacon detection engine.
Correlates Zeek conn.log, dns.log, and ssl.log to produce ranked
beacon probability scores with per-signal breakdowns.
"""

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ATT&CK technique mappings per signal
ATTACK_MAP = {
    "interval_regularity":    {"id": "T1071",   "name": "Application Layer Protocol"},
    "jitter_low":             {"id": "T1571",   "name": "Non-Standard Port"},
    "byte_ratio_uniform":     {"id": "T1095",   "name": "Non-Application Layer Protocol"},
    "session_frequency":      {"id": "T1071.001","name": "Web Protocols"},
    "long_connection":        {"id": "T1071.004","name": "DNS"},
    "sni_cert_mismatch":      {"id": "T1573.002","name": "Asymmetric Cryptography"},
    "dns_entropy_high":       {"id": "T1568.002","name": "Domain Generation Algorithms"},
    "short_cert_lifetime":    {"id": "T1587.003","name": "Digital Certificates"},
    "self_signed_cert":       {"id": "T1587.003","name": "Digital Certificates"},
    "low_ttl_variance":       {"id": "T1568",    "name": "Dynamic Resolution"},
}

DEFAULT_WEIGHTS = {
    "interval_regularity":  0.25,
    "jitter_low":           0.15,
    "byte_ratio_uniform":   0.12,
    "session_frequency":    0.10,
    "long_connection":      0.08,
    "sni_cert_mismatch":    0.10,
    "dns_entropy_high":     0.08,
    "short_cert_lifetime":  0.07,
    "self_signed_cert":     0.03,
    "low_ttl_variance":     0.02,
}


@dataclass
class SignalResult:
    name: str
    score: float          # 0.0 - 1.0
    weight: float
    weighted: float
    evidence: str
    attack: Optional[dict] = None
    fired: bool = False


@dataclass
class BeaconCandidate:
    destination: str
    total_score: float
    confidence: str
    signals: list[SignalResult] = field(default_factory=list)
    connection_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    attack_techniques: list[dict] = field(default_factory=list)
    raw_intervals: list[float] = field(default_factory=list)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    return statistics.stdev(values) / mean


def _interval_regularity_score(intervals: list[float]) -> tuple[float, str]:
    """
    Low CoV = highly regular intervals = beacon-like.
    Returns score 0-1 and evidence string.
    """
    if len(intervals) < 3:
        return 0.0, "insufficient samples"
    cov = _coefficient_of_variation(intervals)
    # CoV < 0.1 is extremely regular, > 0.5 is noisy
    score = max(0.0, 1.0 - (cov / 0.5))
    mean_interval = statistics.mean(intervals)
    return (
        round(score, 3),
        f"CoV={cov:.3f}, mean_interval={mean_interval:.1f}s over {len(intervals)} sessions"
    )


def _jitter_score(intervals: list[float]) -> tuple[float, str]:
    """
    Absolute jitter: mean absolute deviation from mean.
    Low jitter relative to interval = beacon.
    """
    if len(intervals) < 3:
        return 0.0, "insufficient samples"
    mean = statistics.mean(intervals)
    mad = statistics.mean([abs(x - mean) for x in intervals])
    jitter_pct = (mad / mean) if mean > 0 else 1.0
    score = max(0.0, 1.0 - (jitter_pct / 0.3))
    return (
        round(score, 3),
        f"mean_abs_deviation={mad:.2f}s ({jitter_pct*100:.1f}% of mean interval)"
    )


def _byte_ratio_score(orig_bytes: list[int], resp_bytes: list[int]) -> tuple[float, str]:
    """
    Uniform byte ratios across sessions = encoded C2 keep-alive traffic.
    """
    if len(orig_bytes) < 3:
        return 0.0, "insufficient samples"
    ratios = []
    for o, r in zip(orig_bytes, resp_bytes):
        total = o + r
        if total > 0:
            ratios.append(o / total)
    if not ratios:
        return 0.0, "no byte data"
    cov = _coefficient_of_variation(ratios)
    score = max(0.0, 1.0 - (cov / 0.4))
    mean_ratio = statistics.mean(ratios)
    return (
        round(score, 3),
        f"orig_byte_ratio CoV={cov:.3f}, mean_ratio={mean_ratio:.3f}"
    )


def _session_frequency_score(count: int, duration_hours: float) -> tuple[float, str]:
    """
    High session frequency relative to time window = automated beaconing.
    """
    if duration_hours <= 0:
        return 0.0, "no duration"
    rate = count / duration_hours
    # > 60 sessions/hr = highly suspicious
    score = min(1.0, rate / 60.0)
    return (
        round(score, 3),
        f"{count} sessions over {duration_hours:.1f}h = {rate:.1f} sessions/hr"
    )


def _long_connection_score(durations: list[float]) -> tuple[float, str]:
    """
    Persistent long-lived connections = C2 keep-alive.
    """
    if not durations:
        return 0.0, "no duration data"
    mean_dur = statistics.mean(durations)
    # > 300s mean duration is suspicious
    score = min(1.0, mean_dur / 300.0)
    return (
        round(score, 3),
        f"mean_connection_duration={mean_dur:.1f}s"
    )


def _cn_values(subject: str) -> list:
    """Pull the CN value(s) out of a certificate subject DN.

    The subject arrives as a full DN ("CN=example.com,O=Example Inc"), so a
    substring test against the whole string is both too loose and too strict.
    """
    out = []
    for part in subject.split(","):
        part = part.strip()
        if part.lower().startswith("cn="):
            out.append(part[3:].strip().lower())
    return out or [subject.strip().lower()]


def _sni_matches_cn(sni: str, cn: str) -> bool:
    """Wildcard-aware SNI/CN comparison.

    Ported from c2-fingerprint's _san_mismatch_score, which already handled
    this correctly. A wildcard certificate is the common case on the internet;
    treating CN=*.example.com as a mismatch for foo.example.com made this
    signal fire on ordinary TLS.
    """
    sni = sni.strip().lower()
    cn = cn.strip().lower()
    if not sni or not cn:
        return False
    if cn == sni:
        return True
    if cn.startswith("*."):
        base = cn[2:]
        parts = sni.split(".")
        if len(parts) >= 2 and ".".join(parts[1:]) == base:
            return True
    if sni.endswith("." + cn) or cn.endswith("." + sni):
        return True
    return False


def _sni_cert_mismatch_score(sni_set: set, cert_cn_set: set) -> tuple[float, str]:
    """
    SNI hostname not matching the certificate subject CN = possible domain
    fronting or evasion. SANs are not available here: Zeek writes them to
    x509.log, which this tool does not load.
    """
    if not sni_set or not cert_cn_set:
        return 0.0, "no TLS data available"
    cns = []
    for subject in cert_cn_set:
        cns.extend(_cn_values(subject))
    if not cns:
        return 0.0, "no comparisons possible"
    mismatches = 0
    total = 0
    for sni in sni_set:
        total += 1
        if not any(_sni_matches_cn(sni, cn) for cn in cns):
            mismatches += 1
    if total == 0:
        return 0.0, "no comparisons possible"
    score = mismatches / total
    return (
        round(score, 3),
        f"{mismatches}/{total} SNI value(s) unmatched by cert CN ({', '.join(sorted(cns)[:3])})"
    )


def _dns_entropy_score(queries: list[str]) -> tuple[float, str]:
    """
    High subdomain entropy = DGA or DNS tunneling.
    """
    if not queries:
        return 0.0, "no DNS queries"
    entropies = []
    for q in queries:
        sub = q.split(".")[0] if "." in q else q
        entropies.append(_entropy(sub))
    mean_entropy = statistics.mean(entropies)
    # Shannon entropy > 3.5 on subdomain labels is suspicious
    score = min(1.0, mean_entropy / 4.5)
    return (
        round(score, 3),
        f"mean_subdomain_entropy={mean_entropy:.3f} over {len(queries)} queries"
    )


def _cert_lifetime_score(cert_not_before: Optional[str], cert_not_after: Optional[str]) -> tuple[float, str]:
    """
    Short certificate lifetime = attacker-issued cert.
    """
    if not cert_not_before or not cert_not_after:
        return 0.0, "no certificate validity data"
    try:
        fmt = "%Y-%m-%dT%H:%M:%S"
        nb = datetime.strptime(cert_not_before[:19], fmt)
        na = datetime.strptime(cert_not_after[:19], fmt)
        lifetime_days = (na - nb).days
        # < 90 days is suspicious, > 365 is normal
        if lifetime_days <= 0:
            return 1.0, f"invalid cert lifetime: {lifetime_days}d"
        score = max(0.0, 1.0 - (lifetime_days / 365.0))
        return round(score, 3), f"cert_lifetime={lifetime_days}d"
    except Exception:
        return 0.0, "cert date parse error"


def _self_signed_score(issuer: Optional[str], subject: Optional[str]) -> tuple[float, str]:
    if not issuer or not subject:
        return 0.0, "no cert issuer/subject data"
    if issuer.strip().lower() == subject.strip().lower():
        return 1.0, f"self-signed: issuer==subject ({issuer[:60]})"
    return 0.0, "cert appears CA-signed"


def _low_ttl_variance_score(ttl_lists: list[list]) -> tuple[float, str]:
    """
    Low variance in DNS TTLs across responses for a destination = fast-flux adjacent.
    Collects all TTL values from DNS answers, scores low variance as suspicious.
    """
    all_ttls = []
    for ttl_list in ttl_lists:
        if isinstance(ttl_list, list):
            for t in ttl_list:
                try:
                    val = float(t)
                    if val > 0:
                        all_ttls.append(val)
                except (TypeError, ValueError):
                    continue
    if len(all_ttls) < 3:
        return 0.0, "insufficient TTL samples"
    mean_ttl = statistics.mean(all_ttls)
    cov = _coefficient_of_variation(all_ttls)
    # Very low TTL mean (< 60s) combined with low variance = suspicious
    # Normal CDN TTLs are 30-300s with moderate variance
    ttl_score = max(0.0, 1.0 - (mean_ttl / 300.0))  # lower TTL = higher score
    variance_score = max(0.0, 1.0 - (cov / 0.5))     # lower variance = higher score
    score = (ttl_score * 0.6 + variance_score * 0.4)
    return (
        round(score, 3),
        f"mean_ttl={mean_ttl:.1f}s, CoV={cov:.3f} over {len(all_ttls)} TTL values"
    )


def _confidence_label(score: float) -> str:
    if score >= 0.80:
        return "CRITICAL"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    if score >= 0.20:
        return "LOW"
    return "INFORMATIONAL"


def score_candidate(
    destination: str,
    conn_sessions: list[dict],
    dns_queries: list[dict],
    ssl_sessions: list[dict],
    weights: dict,
) -> BeaconCandidate:
    """
    Core scoring function. Takes correlated session data per destination
    and returns a fully scored BeaconCandidate.
    """
    signals = []

    # -- Build interval list from conn timestamps
    # Filter out malformed records with missing/zero timestamps
    raw_ts = [s.get("ts") for s in conn_sessions]
    timestamps = sorted([t for t in raw_ts if t and t > 0])
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    orig_bytes = [s.get("orig_bytes", 0) or 0 for s in conn_sessions]
    resp_bytes = [s.get("resp_bytes", 0) or 0 for s in conn_sessions]
    durations = [s.get("duration", 0) or 0 for s in conn_sessions]
    ports = sorted({s.get("id.resp_p", 0) for s in conn_sessions})
    protocols = sorted({s.get("proto", "") for s in conn_sessions if s.get("proto")})

    duration_hours = (max(timestamps) - min(timestamps)) / 3600.0 if len(timestamps) > 1 else 0.0
    first_seen = str(int(min(timestamps))) if timestamps else ""
    last_seen = str(int(max(timestamps))) if timestamps else ""

    # Signal: interval regularity
    sc, ev = _interval_regularity_score(intervals)
    signals.append(SignalResult(
        name="interval_regularity", score=sc,
        weight=weights.get("interval_regularity", 0),
        weighted=round(sc * weights.get("interval_regularity", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("interval_regularity"),
        fired=sc > 0.3
    ))

    # Signal: jitter
    sc, ev = _jitter_score(intervals)
    signals.append(SignalResult(
        name="jitter_low", score=sc,
        weight=weights.get("jitter_low", 0),
        weighted=round(sc * weights.get("jitter_low", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("jitter_low"),
        fired=sc > 0.3
    ))

    # Signal: byte ratio uniformity
    sc, ev = _byte_ratio_score(orig_bytes, resp_bytes)
    signals.append(SignalResult(
        name="byte_ratio_uniform", score=sc,
        weight=weights.get("byte_ratio_uniform", 0),
        weighted=round(sc * weights.get("byte_ratio_uniform", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("byte_ratio_uniform"),
        fired=sc > 0.3
    ))

    # Signal: session frequency
    sc, ev = _session_frequency_score(len(conn_sessions), duration_hours)
    signals.append(SignalResult(
        name="session_frequency", score=sc,
        weight=weights.get("session_frequency", 0),
        weighted=round(sc * weights.get("session_frequency", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("session_frequency"),
        fired=sc > 0.2
    ))

    # Signal: long connections
    sc, ev = _long_connection_score(durations)
    signals.append(SignalResult(
        name="long_connection", score=sc,
        weight=weights.get("long_connection", 0),
        weighted=round(sc * weights.get("long_connection", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("long_connection"),
        fired=sc > 0.3
    ))

    # Signal: SNI/cert mismatch (from ssl.log)
    sni_set = {s.get("server_name", "") for s in ssl_sessions if s.get("server_name")}
    cert_cn_set = {s.get("subject", "") for s in ssl_sessions if s.get("subject")}
    sc, ev = _sni_cert_mismatch_score(sni_set, cert_cn_set)
    signals.append(SignalResult(
        name="sni_cert_mismatch", score=sc,
        weight=weights.get("sni_cert_mismatch", 0),
        weighted=round(sc * weights.get("sni_cert_mismatch", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("sni_cert_mismatch"),
        fired=sc > 0.4
    ))

    # Signal: DNS entropy
    query_strings = [d.get("query", "") for d in dns_queries if d.get("query")]
    sc, ev = _dns_entropy_score(query_strings)
    signals.append(SignalResult(
        name="dns_entropy_high", score=sc,
        weight=weights.get("dns_entropy_high", 0),
        weighted=round(sc * weights.get("dns_entropy_high", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("dns_entropy_high"),
        fired=sc > 0.4
    ))

    # Signal: cert lifetime (first ssl session with cert data)
    cert_nb = next((s.get("not_valid_before") for s in ssl_sessions if s.get("not_valid_before")), None)
    cert_na = next((s.get("not_valid_after") for s in ssl_sessions if s.get("not_valid_after")), None)
    sc, ev = _cert_lifetime_score(cert_nb, cert_na)
    signals.append(SignalResult(
        name="short_cert_lifetime", score=sc,
        weight=weights.get("short_cert_lifetime", 0),
        weighted=round(sc * weights.get("short_cert_lifetime", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("short_cert_lifetime"),
        fired=sc > 0.5
    ))

    # Signal: self-signed cert
    issuer = next((s.get("issuer") for s in ssl_sessions if s.get("issuer")), None)
    subject = next((s.get("subject") for s in ssl_sessions if s.get("subject")), None)
    sc, ev = _self_signed_score(issuer, subject)
    signals.append(SignalResult(
        name="self_signed_cert", score=sc,
        weight=weights.get("self_signed_cert", 0),
        weighted=round(sc * weights.get("self_signed_cert", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("self_signed_cert"),
        fired=sc > 0.5
    ))

    # Signal: low TTL variance (from dns.log TTLs for this destination)
    ttl_lists = [d.get("TTLs", []) for d in dns_queries]
    sc, ev = _low_ttl_variance_score(ttl_lists)
    signals.append(SignalResult(
        name="low_ttl_variance", score=sc,
        weight=weights.get("low_ttl_variance", 0),
        weighted=round(sc * weights.get("low_ttl_variance", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("low_ttl_variance"),
        fired=sc > 0.5
    ))

    total_score = round(sum(s.weighted for s in signals), 4)
    confidence = _confidence_label(total_score)

    attack_techniques = list({
        (s.attack["id"], s.attack["name"])
        for s in signals if s.fired and s.attack
    })
    attack_techniques = [{"id": t[0], "name": t[1]} for t in attack_techniques]

    return BeaconCandidate(
        destination=destination,
        total_score=total_score,
        confidence=confidence,
        signals=signals,
        connection_count=len(conn_sessions),
        first_seen=first_seen,
        last_seen=last_seen,
        ports=ports,
        protocols=protocols,
        attack_techniques=attack_techniques,
        raw_intervals=intervals[:20],
    )
