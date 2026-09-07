# beacon-score

**Multi-signal C2 beacon detection from Zeek logs or PCAP.**

beacon-score correlates `conn.log`, `dns.log`, and `ssl.log` to produce a ranked list of C2 beacon candidates with per-signal breakdowns, ATT&CK technique mapping, and configurable signal weights. Drop in a PCAP and it handles Zeek invocation automatically (requires Zeek installed and in PATH).

```
$ beacon-score --conn conn.log --dns dns.log --ssl ssl.log --detail

 #   Destination        Score    Confidence     Sessions   ATT&CK
 ──────────────────────────────────────────────────────────────────
 1   185.220.101.45     0.7830   HIGH           180        T1071 T1587.003 T1071.001
 2   194.165.16.11      0.5446   MEDIUM         72         T1095 T1071 T1573.002
 3   45.142.212.100     0.3118   LOW            60         T1071.001 T1568.002
```

---

## Why beacon-score

Most beacon detection tools assume you already have a full SIEM stack running. beacon-score works on what you have: a PCAP from a sensor or a directory of Zeek logs from a capture. No database, no agent, no configuration overhead. Run it in seconds during IR, threat hunting, or lab validation.

The scoring model correlates signals across all three log sources simultaneously. A destination that shows regular connection intervals *and* uniform byte ratios *and* a self-signed certificate scores materially higher than one that only triggers on a single signal. Single-signal detections are how you get noise. Multi-signal correlation is how you get findings.

---

## Signals

Each signal is scored independently (0.0–1.0), weighted, and summed to produce the final beacon probability score. All weights are configurable.

| Signal | ATT&CK | Description |
|---|---|---|
| `interval_regularity` | T1071 | Low coefficient of variation across connection intervals — automated origin |
| `jitter_low` | T1071 | Mean absolute deviation relative to interval mean — non-human timing |
| `byte_ratio_uniform` | T1071 | Uniform orig/resp byte ratios across sessions — encoded keep-alive |
| `session_frequency` | T1071.001 | High session rate relative to time window — automated poll loop |
| `long_connection` | T1071 | Persistent long-lived connections — tunneled channel or keep-alive |
| `sni_cert_mismatch` | T1573.002 | TLS SNI does not match the certificate subject CN — possible domain fronting or evasion. **SAN is not checked (Zeek writes SANs to `x509.log`, which is not read), and wildcard certificates are reported as mismatches.** |
| `dns_entropy_high` | T1568.002 | High Shannon entropy on subdomain labels — DGA indicator for destinations already surfaced by conn-based signals. **Does not detect DNS tunnelling: ports 53/67/68/123/5353 are excluded before candidate generation, so a DNS-tunnelled channel never becomes a candidate.** |
| `short_cert_lifetime` | T1587.003 | Short certificate validity window — attacker-issued ephemeral infrastructure |
| `self_signed_cert` | T1587.003 | Issuer matches subject — attacker-controlled TLS endpoint |
| `low_ttl_variance` | T1568 | Low DNS TTL magnitude and variance for destination — fast-flux adjacent behaviour |

Confidence bands:

| Score | Confidence |
|---|---|
| ≥ 0.80 | CRITICAL |
| ≥ 0.60 | HIGH |
| ≥ 0.40 | MEDIUM |
| ≥ 0.20 | LOW |
| < 0.20 | INFORMATIONAL |

---

## Installation

Requires Python 3.10+ as declared in `pyproject.toml`. (It also runs on 3.9; the declared floor is conservative and untested.)

```bash
git clone https://github.com/0xPersist/beacon-score
cd beacon-score
pip install .
```

With optional Rich terminal output (recommended):

```bash
pip install ".[rich]"
```

---

## Usage

### From Zeek logs

```bash
beacon-score --conn conn.log --dns dns.log --ssl ssl.log
```

Scoring runs with any subset of logs. **Signals whose source is missing score zero and still count toward the total, so an absent log lowers the score rather than being excluded from it.**

Reachable weight by input:

| Input | Max reachable score |
|---|---|
| `conn.log` only | 0.70 of 1.00 |
| `+ dns.log` | 0.80 |
| `+ ssl.log` | 1.00 |

**A plaintext (non-TLS) beacon therefore cannot reach CRITICAL (0.80) no matter how regular it is.** Compare scores only between runs using the same set of logs.

```bash
# conn.log only — interval, jitter, byte ratio, frequency, duration signals
beacon-score --conn conn.log

# conn + dns — adds entropy scoring for destinations already surfaced by conn signals
beacon-score --conn conn.log --dns dns.log
```

### From PCAP

Zeek must be installed and in PATH.

```bash
beacon-score --pcap capture.pcap
```

Zeek is invoked automatically with `base/protocols/conn`, `base/protocols/dns`, and `base/protocols/ssl` loaded. Logs are generated to a temp directory, scored, and cleaned up.

### Output

```bash
# Terminal table + JSON report to file
beacon-score --conn conn.log --dns dns.log --ssl ssl.log --out report.json

# Per-signal breakdown panel for each candidate
beacon-score --conn conn.log --dns dns.log --ssl ssl.log --detail

# JSON only (pipe-friendly)
beacon-score --conn conn.log --json-only | jq '.beacon_candidates[0]'

# Top 5 only, minimum 10 sessions, score threshold
beacon-score --conn conn.log --top 5 --min-sessions 10 --threshold 0.30
```

### Custom weights

Generate a weights file:

```bash
beacon-score --generate-config weights.yaml
```

Edit weights, then pass on every run:

```bash
beacon-score --conn conn.log --config weights.yaml
```

Weights are floats between 0.0 and 1.0. They do not need to sum to 1.0. Setting a weight to 0.0 disables that signal entirely.

---

## JSON report format

```json
{
  "beacon_candidates": [
    {
      "destination": "185.220.101.45",
      "total_score": 0.783,
      "confidence": "HIGH",
      "connection_count": 180,
      "first_seen": "2024-11-14 12:00:00",
      "last_seen": "2024-11-14 17:59:00",
      "ports": [443],
      "protocols": ["tcp"],
      "attack_techniques": [
        {"id": "T1071", "name": "Application Layer Protocol"},
        {"id": "T1587.003", "name": "Digital Certificates"}
      ],
      "signals": [
        {
          "name": "interval_regularity",
          "score": 0.981,
          "weight": 0.25,
          "weighted": 0.2452,
          "fired": true,
          "evidence": "CoV=0.019, mean_interval=60.1s over 179 sessions",
          "attack": {"id": "T1071", "name": "Application Layer Protocol"}
        }
      ],
      "raw_intervals_sample": [60.1, 59.8, 60.3, 60.0]
    }
  ]
}
```

---

## Testing

Generate synthetic logs and run against them:

```bash
python scripts/gen_sample_logs.py
beacon-score --conn sample_logs/conn.log --dns sample_logs/dns.log --ssl sample_logs/ssl.log --detail
```

The sample log generator produces:
- A 60-second regular beacon with self-signed cert (expect HIGH/CRITICAL)
- A 5-minute beacon with moderate jitter (expect MEDIUM)
- DGA-style high-entropy DNS traffic (expect LOW/MEDIUM)
- Normal browsing noise (expect INFORMATIONAL)

Run the test suite:

```bash
pip install pytest
pytest tests/ -v
```

**Known issue:** the suite reports 42 passing tests but `tests/test_beacon_score.py` defines 98. Fourteen class names are declared twice, so Python discards the first definition of each and 56 tests never execute. A green run currently covers 43% of the tests written.

---

## Flags

```
input:
  --pcap FILE           Raw PCAP. Zeek invoked automatically.
  --conn FILE           Zeek conn.log (TSV or JSON, optionally gzipped)
  --dns  FILE           Zeek dns.log
  --ssl  FILE           Zeek ssl.log

output:
  --out FILE            Write JSON report to file
  --json-only           Suppress terminal output, print JSON to stdout
  --detail              Show per-signal breakdown for each candidate
  --top N               Number of candidates to show (default: 20)

scoring:
  --config FILE         YAML or TOML weights config
  --min-sessions N      Minimum session count per destination (default: 5)
  --include-private     Include RFC1918/loopback destinations
  --threshold FLOAT     Only output candidates >= this score

utility:
  --generate-config FILE  Write default weights config and exit
  --version
```

---

## Log format support

Both Zeek log formats are supported and auto-detected:

- **TSV** — classic Zeek format with `#fields` / `#types` headers
- **JSON** — `LogAscii::use_json=T` per-line JSON format
- **Gzipped** — `.log.gz` files are read directly without decompression

---

## Limitations

- Encrypted payloads: byte ratio signals are less reliable over QUIC or HTTP/3 where packet framing differs
- Short capture windows: interval regularity requires at least 3 sessions per destination to score
- IPv6: supported in log parsing, private range filtering covers `::1` and `fe80::`
- PCAP mode requires Zeek — if unavailable, pre-generate logs with `zeek -r capture.pcap LogAscii::use_json=T`

---

## Related

- [RITA](https://github.com/activecm/rita) — full beacon analysis platform, requires MongoDB
- [Zeek](https://zeek.org) — network analysis framework
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — technique visualization

---

## License

MIT
