"""
Tests for beacon-score engine, parsers, correlator, and config.
"""

import json
import os
import tempfile
import pytest

from beacon_score.engine import (
    _entropy,
    _coefficient_of_variation,
    _interval_regularity_score,
    _jitter_score,
    _byte_ratio_score,
    _session_frequency_score,
    _long_connection_score,
    _dns_entropy_score,
    _low_ttl_variance_score,
    _confidence_label,
    score_candidate,
    DEFAULT_WEIGHTS,
)
from beacon_score.parsers import load_conn_log, load_dns_log, load_ssl_log
from beacon_score.correlator import correlate_and_score, _is_private
from beacon_score.config import load_weights, generate_default_config
from beacon_score.renderer import render_json_output


# ── Engine unit tests ─────────────────────────────────────────────────────────

class TestEntropy:
    def test_empty(self):
        assert _entropy("") == 0.0

    def test_uniform(self):
        assert _entropy("aaaa") == 0.0

    def test_high_entropy(self):
        assert _entropy("a1b2c3d4e5f6") > 3.0

    def test_known(self):
        # "ab" has entropy of 1.0
        assert abs(_entropy("ab") - 1.0) < 0.001


class TestCoV:
    def test_zero_mean(self):
        assert _coefficient_of_variation([0, 0, 0]) == 0.0

    def test_single_value(self):
        assert _coefficient_of_variation([5.0]) == 0.0

    def test_uniform(self):
        assert _coefficient_of_variation([10, 10, 10]) == 0.0

    def test_varied(self):
        cov = _coefficient_of_variation([1, 2, 3, 4, 5])
        assert cov > 0.4


class TestIntervalRegularity:
    def test_insufficient(self):
        score, ev = _interval_regularity_score([60])
        assert score == 0.0

    def test_perfect_regularity(self):
        score, _ = _interval_regularity_score([60.0] * 30)
        assert score > 0.95

    def test_irregular(self):
        import random
        random.seed(1)
        intervals = [random.uniform(1, 3600) for _ in range(50)]
        score, _ = _interval_regularity_score(intervals)
        assert score < 0.3


class TestJitter:
    def test_zero_jitter(self):
        score, ev = _jitter_score([60.0] * 20)
        assert score > 0.9

    def test_high_jitter(self):
        import random
        random.seed(2)
        intervals = [random.uniform(10, 600) for _ in range(20)]
        score, _ = _jitter_score(intervals)
        assert score < 0.5


class TestByteRatio:
    def test_uniform_ratio(self):
        orig = [128] * 20
        resp = [64] * 20
        score, _ = _byte_ratio_score(orig, resp)
        assert score > 0.9

    def test_varied_ratio(self):
        import random
        random.seed(3)
        orig = [random.randint(100, 50000) for _ in range(20)]
        resp = [random.randint(500, 200000) for _ in range(20)]
        score, _ = _byte_ratio_score(orig, resp)
        assert score < 0.7


class TestSessionFrequency:
    def test_high_rate(self):
        score, ev = _session_frequency_score(720, 2.0)  # 360/hr
        assert score >= 1.0

    def test_low_rate(self):
        score, _ = _session_frequency_score(5, 24.0)
        assert score < 0.1

    def test_zero_duration(self):
        score, _ = _session_frequency_score(100, 0.0)
        assert score == 0.0


class TestConfidenceLabel:
    def test_labels(self):
        assert _confidence_label(0.85) == "CRITICAL"
        assert _confidence_label(0.65) == "HIGH"
        assert _confidence_label(0.45) == "MEDIUM"
        assert _confidence_label(0.25) == "LOW"
        assert _confidence_label(0.05) == "INFORMATIONAL"

    def test_boundary_critical(self):
        assert _confidence_label(0.80) == "CRITICAL"

    def test_boundary_high(self):
        assert _confidence_label(0.60) == "HIGH"


class TestDnsEntropy:
    def test_high_entropy_subdomains(self):
        queries = [f"xk3j9mf2b1{'abcde'[:i+1]}.example.com" for i in range(20)]
        score, _ = _dns_entropy_score(queries)
        assert score > 0.5

    def test_normal_subdomains(self):
        queries = ["www.google.com", "mail.google.com", "api.google.com"]
        score, _ = _dns_entropy_score(queries)
        assert score < 0.6

    def test_empty(self):
        score, ev = _dns_entropy_score([])
        assert score == 0.0
        assert "no DNS" in ev


class TestLowTtlVariance:
    def test_insufficient_samples(self):
        score, ev = _low_ttl_variance_score([[30.0], [30.0]])
        assert score == 0.0
        assert "insufficient" in ev

    def test_low_ttl_low_variance(self):
        # Very short, very uniform TTLs = suspicious
        ttl_lists = [[30.0]] * 20
        score, ev = _low_ttl_variance_score(ttl_lists)
        assert score > 0.5

    def test_normal_ttl(self):
        # Normal CDN-style TTLs with variance
        import random
        random.seed(7)
        ttl_lists = [[random.uniform(60, 300)] for _ in range(20)]
        score, _ = _low_ttl_variance_score(ttl_lists)
        # Should not be extremely high
        assert score < 0.9

    def test_empty_ttl_lists(self):
        score, _ = _low_ttl_variance_score([[], [], []])
        assert score == 0.0

    def test_invalid_ttl_values_skipped(self):
        # Should not raise, should skip non-numeric values
        ttl_lists = [["invalid", None, 30.0], [30.0, 30.0]]
        score, _ = _low_ttl_variance_score(ttl_lists)
        assert 0.0 <= score <= 1.0


# ── Integration: score_candidate ─────────────────────────────────────────────

class TestScoreCandidate:
    def _make_beacon_sessions(self, count=60, interval=60.0, jitter_pct=0.02):
        import random
        random.seed(10)
        ts = 1700000000.0
        sessions = []
        for _ in range(count):
            ts += interval + random.uniform(-interval * jitter_pct, interval * jitter_pct)
            sessions.append({
                "ts": ts,
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": 0.2,
                "orig_bytes": 144,
                "resp_bytes": 72,
            })
        return sessions

    def test_high_score_beacon(self):
        sessions = self._make_beacon_sessions(60, 60.0, 0.01)
        candidate = score_candidate(
            destination="185.220.101.45",
            conn_sessions=sessions,
            dns_queries=[],
            ssl_sessions=[{
                "server_name": "updates.185io",
                "subject": "CN=185.220.101.45",
                "issuer": "CN=185.220.101.45",
            }],
            weights=DEFAULT_WEIGHTS,
        )
        assert candidate.total_score > 0.30
        assert candidate.destination == "185.220.101.45"
        assert len(candidate.signals) > 0

    def test_low_score_noise(self):
        import random
        random.seed(99)
        ts = 1700000000.0
        sessions = []
        for _ in range(30):
            ts += random.uniform(5, 3600)
            sessions.append({
                "ts": ts,
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": random.uniform(1, 60),
                "orig_bytes": random.randint(1000, 100000),
                "resp_bytes": random.randint(5000, 500000),
            })
        candidate = score_candidate(
            destination="142.250.80.46",
            conn_sessions=sessions,
            dns_queries=[],
            ssl_sessions=[],
            weights=DEFAULT_WEIGHTS,
        )
        assert candidate.total_score < 0.4

    def test_all_signals_present(self):
        sessions = self._make_beacon_sessions(20)
        candidate = score_candidate("1.2.3.4", sessions, [], [], DEFAULT_WEIGHTS)
        signal_names = {s.name for s in candidate.signals}
        expected = {
            "interval_regularity", "jitter_low", "byte_ratio_uniform",
            "session_frequency", "long_connection", "sni_cert_mismatch",
            "dns_entropy_high", "short_cert_lifetime", "self_signed_cert",
            "low_ttl_variance",
        }
        assert expected == signal_names

    def test_zero_timestamp_filtered(self):
        # Sessions with ts=0 should be filtered and not corrupt duration_hours
        import random
        random.seed(11)
        ts = 1700000000.0
        sessions = []
        for i in range(30):
            ts += 60.0
            sessions.append({
                "ts": ts,
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": 0.2,
                "orig_bytes": 144,
                "resp_bytes": 72,
            })
        # Insert a malformed record with ts=0
        sessions.insert(5, {"ts": 0, "id.resp_p": 443, "proto": "tcp",
                             "duration": 0.2, "orig_bytes": 144, "resp_bytes": 72})
        candidate = score_candidate("1.2.3.4", sessions, [], [], DEFAULT_WEIGHTS)
        # Duration should be based on real timestamps only; session_frequency should
        # not be near zero due to a spurious huge duration window
        session_freq_signal = next(s for s in candidate.signals if s.name == "session_frequency")
        assert session_freq_signal.score > 0.1

    def test_ports_sorted(self):
        import random
        random.seed(12)
        ts = 1700000000.0
        sessions = []
        for port in [8443, 443, 80, 4443]:
            for _ in range(5):
                ts += 60.0
                sessions.append({"ts": ts, "id.resp_p": port, "proto": "tcp",
                                  "duration": 0.2, "orig_bytes": 100, "resp_bytes": 50})
        candidate = score_candidate("1.2.3.4", sessions, [], [], DEFAULT_WEIGHTS)
        assert candidate.ports == sorted(candidate.ports)

    def test_protocols_sorted(self):
        ts = 1700000000.0
        sessions = []
        for proto in ["udp", "tcp"]:
            for _ in range(5):
                ts += 60.0
                sessions.append({"ts": ts, "id.resp_p": 443, "proto": proto,
                                  "duration": 0.2, "orig_bytes": 100, "resp_bytes": 50})
        candidate = score_candidate("1.2.3.4", sessions, [], [], DEFAULT_WEIGHTS)
        assert candidate.protocols == sorted(candidate.protocols)


# ── Parser tests ──────────────────────────────────────────────────────────────

class TestParsers:
    def _write_tsv_conn_log(self, path):
        lines = [
            "#separator \\x09",
            "#set_separator ,",
            "#empty_field (empty)",
            "#unset_field -",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount",
            "1700000000.0\tCabc123\t10.0.0.1\t54321\t185.220.101.45\t443\ttcp\tssl\t0.25\t144\t72\tSF\t4\t3",
            "1700000060.0\tCabc124\t10.0.0.1\t54322\t185.220.101.45\t443\ttcp\tssl\t0.23\t144\t72\tSF\t4\t3",
        ]
        with open(path, "w") as f:
            f.write("\n".join(lines))

    def test_load_json_conn(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            records = [
                {"ts": 1700000000.0, "uid": "C1", "id.orig_h": "10.0.0.1",
                 "id.orig_p": 54321, "id.resp_h": "185.220.101.45",
                 "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                 "duration": 0.25, "orig_bytes": 144, "resp_bytes": 72,
                 "conn_state": "SF"},
            ]
            for r in records:
                f.write(json.dumps(r) + "\n")
            path = f.name
        try:
            loaded = load_conn_log(path)
            assert len(loaded) == 1
            assert loaded[0]["id.resp_h"] == "185.220.101.45"
        finally:
            os.unlink(path)

    def test_load_tsv_conn(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            self._write_tsv_conn_log(path)
            loaded = load_conn_log(path)
            assert len(loaded) == 2
            assert loaded[0]["id.resp_h"] == "185.220.101.45"
            assert loaded[0]["id.resp_p"] == 443
        finally:
            os.unlink(path)

    def test_empty_log(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            loaded = load_conn_log(path)
            assert loaded == []
        finally:
            os.unlink(path)

    def test_missing_log(self):
        loaded = load_conn_log("/nonexistent/path/conn.log")
        assert loaded == []

    def test_dns_json_answers_is_list(self):
        """JSON-format dns.log answers should come through as a list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            record = {
                "ts": 1700000000.0, "uid": "D1",
                "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
                "query": "evil.example.com", "qtype_name": "A",
                "answers": ["185.220.101.45", "185.220.101.46"],
                "TTLs": [30.0, 30.0], "rcode_name": "NOERROR",
            }
            f.write(json.dumps(record) + "\n")
            path = f.name
        try:
            loaded = load_dns_log(path)
            assert len(loaded) == 1
            assert isinstance(loaded[0]["answers"], list)
            assert "185.220.101.45" in loaded[0]["answers"]
        finally:
            os.unlink(path)

    def test_dns_tsv_answers_normalized_to_list(self):
        """TSV-format dns.log answers arrive as comma-separated string and must be normalized."""
        lines = [
            "#separator \\x09",
            "#set_separator ,",
            "#empty_field (empty)",
            "#unset_field -",
            "#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\tqtype_name\tanswers\tTTLs\trcode_name",
            "#types\ttime\tstring\taddr\taddr\tstring\tstring\tvector[string]\tvector[interval]\tstring",
            "1700000000.0\tD2\t10.0.0.1\t8.8.8.8\tevil.example.com\tA\t185.220.101.45,185.220.101.46\t30.0,30.0\tNOERROR",
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("\n".join(lines))
            path = f.name
        try:
            loaded = load_dns_log(path)
            assert len(loaded) == 1
            assert isinstance(loaded[0]["answers"], list), "TSV answers must be normalized to list"
            assert "185.220.101.45" in loaded[0]["answers"]
        finally:
            os.unlink(path)


# ── Private IP detection ──────────────────────────────────────────────────────

class TestPrivateFilter:
    def test_private(self):
        assert _is_private("192.168.1.1")
        assert _is_private("10.0.0.1")
        assert _is_private("172.16.0.1")
        assert _is_private("127.0.0.1")

    def test_public(self):
        assert not _is_private("185.220.101.45")
        assert not _is_private("8.8.8.8")

    def test_ipv6_loopback(self):
        assert _is_private("::1")

    def test_ipv6_link_local(self):
        assert _is_private("fe80::1")


# ── Correlator integration test ───────────────────────────────────────────────

class TestCorrelator:
    def test_end_to_end(self, tmp_path):
        import random
        random.seed(42)

        ts = 1700000000.0
        conn_records = []
        for i in range(120):
            ts += 60.0 + random.uniform(-1.0, 1.0)
            conn_records.append({
                "ts": round(ts, 3),
                "uid": f"C{i:06d}",
                "id.orig_h": "10.0.0.50",
                "id.orig_p": 50000 + i,
                "id.resp_h": "185.220.101.45",
                "id.resp_p": 443,
                "proto": "tcp",
                "service": "ssl",
                "duration": 0.2,
                "orig_bytes": 144,
                "resp_bytes": 72,
                "conn_state": "SF",
            })

        conn_path = tmp_path / "conn.log"
        with open(conn_path, "w") as f:
            for r in conn_records:
                f.write(json.dumps(r) + "\n")

        candidates = correlate_and_score(
            conn_path=str(conn_path),
            dns_path="",
            ssl_path="",
            min_sessions=5,
            exclude_private=True,
            top_n=10,
        )

        assert len(candidates) == 1
        assert candidates[0].destination == "185.220.101.45"
        assert candidates[0].total_score > 0.25
        assert candidates[0].connection_count == 120

    def test_min_sessions_filter(self, tmp_path):
        """Destinations below min_sessions threshold should be excluded."""
        ts = 1700000000.0
        conn_records = []
        for i in range(4):
            ts += 60.0
            conn_records.append({
                "ts": ts, "uid": f"C{i}", "id.orig_h": "10.0.0.1",
                "id.orig_p": 50000, "id.resp_h": "8.8.8.8",
                "id.resp_p": 443, "proto": "tcp", "duration": 0.2,
                "orig_bytes": 100, "resp_bytes": 50, "conn_state": "SF",
            })
        conn_path = tmp_path / "conn.log"
        with open(conn_path, "w") as f:
            for r in conn_records:
                f.write(json.dumps(r) + "\n")
        candidates = correlate_and_score(
            conn_path=str(conn_path), dns_path="", ssl_path="",
            min_sessions=5, exclude_private=False,
        )
        assert len(candidates) == 0

    def test_private_excluded_by_default(self, tmp_path):
        ts = 1700000000.0
        conn_records = []
        for i in range(20):
            ts += 60.0
            conn_records.append({
                "ts": ts, "uid": f"C{i}", "id.orig_h": "10.0.0.1",
                "id.orig_p": 50000, "id.resp_h": "192.168.1.100",
                "id.resp_p": 443, "proto": "tcp", "duration": 0.2,
                "orig_bytes": 100, "resp_bytes": 50, "conn_state": "SF",
            })
        conn_path = tmp_path / "conn.log"
        with open(conn_path, "w") as f:
            for r in conn_records:
                f.write(json.dumps(r) + "\n")
        candidates = correlate_and_score(
            conn_path=str(conn_path), dns_path="", ssl_path="",
            min_sessions=5, exclude_private=True,
        )
        assert len(candidates) == 0

    def test_excluded_ports_skipped(self, tmp_path):
        """Port 53 should be excluded from beacon analysis."""
        ts = 1700000000.0
        conn_records = []
        for i in range(20):
            ts += 60.0
            conn_records.append({
                "ts": ts, "uid": f"C{i}", "id.orig_h": "10.0.0.1",
                "id.orig_p": 50000, "id.resp_h": "8.8.8.8",
                "id.resp_p": 53, "proto": "udp", "duration": 0.05,
                "orig_bytes": 60, "resp_bytes": 120, "conn_state": "SF",
            })
        conn_path = tmp_path / "conn.log"
        with open(conn_path, "w") as f:
            for r in conn_records:
                f.write(json.dumps(r) + "\n")
        candidates = correlate_and_score(
            conn_path=str(conn_path), dns_path="", ssl_path="",
            min_sessions=5, exclude_private=False,
        )
        assert len(candidates) == 0


# ── Config tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_default_weights(self):
        weights = load_weights(None)
        assert "interval_regularity" in weights
        assert "low_ttl_variance" in weights
        assert weights["interval_regularity"] == DEFAULT_WEIGHTS["interval_regularity"]

    def test_yaml_config(self, tmp_path):
        config_path = tmp_path / "weights.yaml"
        content = "weights:\n  interval_regularity: 0.50\n  jitter_low: 0.20\n"
        with open(config_path, "w") as f:
            f.write(content)
        weights = load_weights(str(config_path))
        assert weights["interval_regularity"] == 0.50
        assert weights["jitter_low"] == 0.20
        # unchanged defaults preserved
        assert weights["byte_ratio_uniform"] == DEFAULT_WEIGHTS["byte_ratio_uniform"]

    def test_invalid_weight_range(self, tmp_path):
        config_path = tmp_path / "bad.yaml"
        with open(config_path, "w") as f:
            f.write("weights:\n  interval_regularity: 5.0\n")
        with pytest.raises(ValueError):
            load_weights(str(config_path))

    def test_weight_zero_is_valid(self, tmp_path):
        config_path = tmp_path / "zero.yaml"
        with open(config_path, "w") as f:
            f.write("weights:\n  interval_regularity: 0.0\n")
        weights = load_weights(str(config_path))
        assert weights["interval_regularity"] == 0.0

    def test_missing_config(self):
        with pytest.raises(FileNotFoundError):
            load_weights("/nonexistent/weights.yaml")

    def test_generate_yaml_config(self, tmp_path):
        out = tmp_path / "out.yaml"
        generate_default_config(str(out), fmt="yaml")
        assert out.exists()
        weights = load_weights(str(out))
        assert weights == DEFAULT_WEIGHTS

    def test_generate_toml_config(self, tmp_path):
        out = tmp_path / "out.toml"
        generate_default_config(str(out), fmt="toml")
        assert out.exists()
        # File should be non-empty and contain weight keys
        content = out.read_text()
        assert "interval_regularity" in content
        assert "[weights]" in content


# ── Renderer tests ────────────────────────────────────────────────────────────

class TestRenderer:
    def _make_candidate(self, seed=5):
        import random
        random.seed(seed)
        ts = 1700000000.0
        sessions = []
        for _ in range(30):
            ts += 60.0
            sessions.append({
                "ts": ts, "id.resp_p": 443, "proto": "tcp",
                "duration": 0.2, "orig_bytes": 144, "resp_bytes": 72,
            })
        return score_candidate("1.2.3.4", sessions, [], [], DEFAULT_WEIGHTS)

    def test_json_output_structure(self):
        candidate = self._make_candidate()
        output = render_json_output([candidate])
        data = json.loads(output)
        assert "beacon_candidates" in data
        assert len(data["beacon_candidates"]) == 1
        bc = data["beacon_candidates"][0]
        assert "total_score" in bc
        assert "confidence" in bc
        assert "signals" in bc
        assert "attack_techniques" in bc
        assert "first_seen" in bc
        assert "last_seen" in bc
        assert "ports" in bc
        assert "protocols" in bc
        assert isinstance(bc["signals"], list)

    def test_json_signal_fields(self):
        candidate = self._make_candidate()
        output = render_json_output([candidate])
        data = json.loads(output)
        sig = data["beacon_candidates"][0]["signals"][0]
        for field in ("name", "score", "weight", "weighted", "fired", "evidence"):
            assert field in sig

    def test_json_empty_candidates(self):
        output = render_json_output([])
        data = json.loads(output)
        assert data["beacon_candidates"] == []

    def test_fallback_summary_no_rich(self, capsys):
        """_fallback_summary should print without raising even with empty candidates."""
        from beacon_score.renderer import _fallback_summary
        _fallback_summary([])
        captured = capsys.readouterr()
        assert "Destination" in captured.out

    def test_fallback_detail_no_rich(self, capsys):
        from beacon_score.renderer import _fallback_detail
        candidate = self._make_candidate()
        _fallback_detail(candidate)
        captured = capsys.readouterr()
        assert candidate.destination in captured.out
        assert candidate.confidence in captured.out

    def test_ts_to_human_fixed_epoch(self):
        """
        Zeek timestamps are epoch seconds and render as UTC wall time. Pinned to
        an exact string: the formatter carries no %z/%Z, so moving from the
        deprecated naive utcfromtimestamp() to a tz-aware datetime must not
        change a single character of output.
        """
        from beacon_score.renderer import _ts_to_human
        assert _ts_to_human("1700000000") == "2023-11-14 22:13:20"
        assert _ts_to_human("1700000000.0") == "2023-11-14 22:13:20"

    def test_ts_to_human_rejects_junk(self):
        from beacon_score.renderer import _ts_to_human
        assert _ts_to_human("0") == "unknown"
        assert _ts_to_human("-1") == "unknown"
        assert _ts_to_human("") == "unknown"
        assert _ts_to_human("not-a-timestamp") == "not-a-timestamp"



# ══════════════════════════════════════════════════════════════════════════════
# SECOND SUITE.
#
# These classes previously reused the names of the classes above, so Python
# discarded the first definition of each and 56 tests never ran. They are now
# suffixed Round2 so both suites execute (42 -> 98 collected).
#
# Note that most of this block duplicates the first suite: of the 40 tests here,
# 36 are byte-identical to a test above. Only four are unique:
#   TestScoreCandidateRound2.test_all_signals_present
#   TestConfigRound2.test_default_weights
#   TestConfigRound2.test_yaml_config
#   TestRendererRound2.test_json_output_structure
# Folding those four into the first suite and deleting the rest would give the
# same coverage in roughly 60 tests instead of 98.
# ══════════════════════════════════════════════════════════════════════════════

# ── Engine unit tests ─────────────────────────────────────────────────────────

class TestEntropyRound2:
    def test_empty(self):
        assert _entropy("") == 0.0

    def test_uniform(self):
        assert _entropy("aaaa") == 0.0

    def test_high_entropy(self):
        assert _entropy("a1b2c3d4e5f6") > 3.0

    def test_known(self):
        # "ab" has entropy of 1.0
        assert abs(_entropy("ab") - 1.0) < 0.001


class TestCoVRound2:
    def test_zero_mean(self):
        assert _coefficient_of_variation([0, 0, 0]) == 0.0

    def test_single_value(self):
        assert _coefficient_of_variation([5.0]) == 0.0

    def test_uniform(self):
        assert _coefficient_of_variation([10, 10, 10]) == 0.0

    def test_varied(self):
        cov = _coefficient_of_variation([1, 2, 3, 4, 5])
        assert cov > 0.4


class TestIntervalRegularityRound2:
    def test_insufficient(self):
        score, ev = _interval_regularity_score([60])
        assert score == 0.0

    def test_perfect_regularity(self):
        score, _ = _interval_regularity_score([60.0] * 30)
        assert score > 0.95

    def test_irregular(self):
        import random
        random.seed(1)
        intervals = [random.uniform(1, 3600) for _ in range(50)]
        score, _ = _interval_regularity_score(intervals)
        assert score < 0.3


class TestJitterRound2:
    def test_zero_jitter(self):
        score, ev = _jitter_score([60.0] * 20)
        assert score > 0.9

    def test_high_jitter(self):
        import random
        random.seed(2)
        intervals = [random.uniform(10, 600) for _ in range(20)]
        score, _ = _jitter_score(intervals)
        assert score < 0.5


class TestByteRatioRound2:
    def test_uniform_ratio(self):
        orig = [128] * 20
        resp = [64] * 20
        score, _ = _byte_ratio_score(orig, resp)
        assert score > 0.9

    def test_varied_ratio(self):
        import random
        random.seed(3)
        orig = [random.randint(100, 50000) for _ in range(20)]
        resp = [random.randint(500, 200000) for _ in range(20)]
        score, _ = _byte_ratio_score(orig, resp)
        assert score < 0.7


class TestSessionFrequencyRound2:
    def test_high_rate(self):
        score, ev = _session_frequency_score(720, 2.0)  # 360/hr
        assert score >= 1.0

    def test_low_rate(self):
        score, _ = _session_frequency_score(5, 24.0)
        assert score < 0.1

    def test_zero_duration(self):
        score, _ = _session_frequency_score(100, 0.0)
        assert score == 0.0


class TestConfidenceLabelRound2:
    def test_labels(self):
        assert _confidence_label(0.85) == "CRITICAL"
        assert _confidence_label(0.65) == "HIGH"
        assert _confidence_label(0.45) == "MEDIUM"
        assert _confidence_label(0.25) == "LOW"
        assert _confidence_label(0.05) == "INFORMATIONAL"


class TestDnsEntropyRound2:
    def test_high_entropy_subdomains(self):
        queries = [f"xk3j9mf2b1{'abcde'[:i+1]}.example.com" for i in range(20)]
        score, _ = _dns_entropy_score(queries)
        assert score > 0.5

    def test_normal_subdomains(self):
        queries = ["www.google.com", "mail.google.com", "api.google.com"]
        score, _ = _dns_entropy_score(queries)
        assert score < 0.6


# ── Integration: score_candidate ─────────────────────────────────────────────

class TestScoreCandidateRound2:
    def _make_beacon_sessions(self, count=60, interval=60.0, jitter_pct=0.02):
        import random
        random.seed(10)
        ts = 1700000000.0
        sessions = []
        for _ in range(count):
            ts += interval + random.uniform(-interval * jitter_pct, interval * jitter_pct)
            sessions.append({
                "ts": ts,
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": 0.2,
                "orig_bytes": 144,
                "resp_bytes": 72,
            })
        return sessions

    def test_high_score_beacon(self):
        sessions = self._make_beacon_sessions(60, 60.0, 0.01)
        candidate = score_candidate(
            destination="185.220.101.45",
            conn_sessions=sessions,
            dns_queries=[],
            ssl_sessions=[{
                "server_name": "updates.185io",
                "subject": "CN=185.220.101.45",
                "issuer": "CN=185.220.101.45",
            }],
            weights=DEFAULT_WEIGHTS,
        )
        assert candidate.total_score > 0.30
        assert candidate.destination == "185.220.101.45"
        assert len(candidate.signals) > 0

    def test_low_score_noise(self):
        import random
        random.seed(99)
        ts = 1700000000.0
        sessions = []
        for _ in range(30):
            ts += random.uniform(5, 3600)
            sessions.append({
                "ts": ts,
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": random.uniform(1, 60),
                "orig_bytes": random.randint(1000, 100000),
                "resp_bytes": random.randint(5000, 500000),
            })
        candidate = score_candidate(
            destination="142.250.80.46",
            conn_sessions=sessions,
            dns_queries=[],
            ssl_sessions=[],
            weights=DEFAULT_WEIGHTS,
        )
        assert candidate.total_score < 0.4

    def test_all_signals_present(self):
        sessions = self._make_beacon_sessions(20)
        candidate = score_candidate("1.2.3.4", sessions, [], [], DEFAULT_WEIGHTS)
        signal_names = {s.name for s in candidate.signals}
        expected = {"interval_regularity", "jitter_low", "byte_ratio_uniform",
                    "session_frequency", "long_connection"}
        assert expected.issubset(signal_names)


# ── Parser tests ──────────────────────────────────────────────────────────────

class TestParsersRound2:
    def _write_json_log(self, path, records):
        with open(path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def _write_tsv_conn_log(self, path):
        lines = [
            "#separator \\x09",
            "#set_separator ,",
            "#empty_field (empty)",
            "#unset_field -",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount",
            "1700000000.0\tCabc123\t10.0.0.1\t54321\t185.220.101.45\t443\ttcp\tssl\t0.25\t144\t72\tSF\t4\t3",
            "1700000060.0\tCabc124\t10.0.0.1\t54322\t185.220.101.45\t443\ttcp\tssl\t0.23\t144\t72\tSF\t4\t3",
        ]
        with open(path, "w") as f:
            f.write("\n".join(lines))

    def test_load_json_conn(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            records = [
                {"ts": 1700000000.0, "uid": "C1", "id.orig_h": "10.0.0.1",
                 "id.orig_p": 54321, "id.resp_h": "185.220.101.45",
                 "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                 "duration": 0.25, "orig_bytes": 144, "resp_bytes": 72,
                 "conn_state": "SF"},
            ]
            for r in records:
                f.write(json.dumps(r) + "\n")
            path = f.name
        try:
            loaded = load_conn_log(path)
            assert len(loaded) == 1
            assert loaded[0]["id.resp_h"] == "185.220.101.45"
        finally:
            os.unlink(path)

    def test_load_tsv_conn(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            self._write_tsv_conn_log(path)
            loaded = load_conn_log(path)
            assert len(loaded) == 2
            assert loaded[0]["id.resp_h"] == "185.220.101.45"
            assert loaded[0]["id.resp_p"] == 443
        finally:
            os.unlink(path)

    def test_empty_log(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            loaded = load_conn_log(path)
            assert loaded == []
        finally:
            os.unlink(path)

    def test_missing_log(self):
        loaded = load_conn_log("/nonexistent/path/conn.log")
        assert loaded == []


# ── Private IP detection ──────────────────────────────────────────────────────

class TestPrivateFilterRound2:
    def test_private(self):
        assert _is_private("192.168.1.1")
        assert _is_private("10.0.0.1")
        assert _is_private("172.16.0.1")
        assert _is_private("127.0.0.1")

    def test_public(self):
        assert not _is_private("185.220.101.45")
        assert not _is_private("8.8.8.8")


# ── Correlator integration test ───────────────────────────────────────────────

class TestCorrelatorRound2:
    def test_end_to_end(self, tmp_path):
        import random
        random.seed(42)

        ts = 1700000000.0
        conn_records = []
        for i in range(120):
            ts += 60.0 + random.uniform(-1.0, 1.0)
            conn_records.append({
                "ts": round(ts, 3),
                "uid": f"C{i:06d}",
                "id.orig_h": "10.0.0.50",
                "id.orig_p": 50000 + i,
                "id.resp_h": "185.220.101.45",
                "id.resp_p": 443,
                "proto": "tcp",
                "service": "ssl",
                "duration": 0.2,
                "orig_bytes": 144,
                "resp_bytes": 72,
                "conn_state": "SF",
            })

        conn_path = tmp_path / "conn.log"
        with open(conn_path, "w") as f:
            for r in conn_records:
                f.write(json.dumps(r) + "\n")

        candidates = correlate_and_score(
            conn_path=str(conn_path),
            dns_path="",
            ssl_path="",
            min_sessions=5,
            exclude_private=True,
            top_n=10,
        )

        assert len(candidates) == 1
        assert candidates[0].destination == "185.220.101.45"
        assert candidates[0].total_score > 0.25
        assert candidates[0].connection_count == 120


# ── Config tests ──────────────────────────────────────────────────────────────

class TestConfigRound2:
    def test_default_weights(self):
        weights = load_weights(None)
        assert "interval_regularity" in weights
        assert weights["interval_regularity"] == DEFAULT_WEIGHTS["interval_regularity"]

    def test_yaml_config(self, tmp_path):
        config_path = tmp_path / "weights.yaml"
        content = "weights:\n  interval_regularity: 0.50\n  jitter_low: 0.20\n"
        with open(config_path, "w") as f:
            f.write(content)
        weights = load_weights(str(config_path))
        assert weights["interval_regularity"] == 0.50
        assert weights["jitter_low"] == 0.20
        # unchanged defaults
        assert weights["byte_ratio_uniform"] == DEFAULT_WEIGHTS["byte_ratio_uniform"]

    def test_invalid_weight_range(self, tmp_path):
        config_path = tmp_path / "bad.yaml"
        with open(config_path, "w") as f:
            f.write("weights:\n  interval_regularity: 5.0\n")
        with pytest.raises(ValueError):
            load_weights(str(config_path))

    def test_missing_config(self):
        with pytest.raises(FileNotFoundError):
            load_weights("/nonexistent/weights.yaml")

    def test_generate_yaml_config(self, tmp_path):
        out = tmp_path / "out.yaml"
        generate_default_config(str(out), fmt="yaml")
        assert out.exists()
        weights = load_weights(str(out))
        assert weights == DEFAULT_WEIGHTS


# ── Renderer test ─────────────────────────────────────────────────────────────

class TestRendererRound2:
    def test_json_output_structure(self):
        import random
        random.seed(5)
        ts = 1700000000.0
        sessions = []
        for _ in range(30):
            ts += 60.0
            sessions.append({
                "ts": ts, "id.resp_p": 443, "proto": "tcp",
                "duration": 0.2, "orig_bytes": 144, "resp_bytes": 72,
            })
        from beacon_score.engine import score_candidate
        candidate = score_candidate("1.2.3.4", sessions, [], [], DEFAULT_WEIGHTS)
        output = render_json_output([candidate])
        data = json.loads(output)
        assert "beacon_candidates" in data
        assert len(data["beacon_candidates"]) == 1
        bc = data["beacon_candidates"][0]
        assert "total_score" in bc
        assert "confidence" in bc
        assert "signals" in bc
        assert "attack_techniques" in bc
        assert isinstance(bc["signals"], list)
