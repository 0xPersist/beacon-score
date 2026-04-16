"""
PCAP ingestion handler.
If a PCAP is provided instead of Zeek logs, auto-invokes Zeek to generate
conn.log, dns.log, and ssl.log in a temp directory.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ZEEK_SCRIPTS = [
    "base/protocols/conn",
    "base/protocols/dns",
    "base/protocols/ssl",
]


def zeek_available() -> bool:
    return shutil.which("zeek") is not None or shutil.which("bro") is not None


def _zeek_bin() -> str:
    return shutil.which("zeek") or shutil.which("bro") or "zeek"


def generate_logs_from_pcap(pcap_path: str, output_dir: str = None) -> dict:
    """
    Run Zeek against a PCAP file and return paths to generated log files.
    Returns dict with keys: conn, dns, ssl, tmpdir (caller must clean up tmpdir).
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    if not zeek_available():
        raise RuntimeError(
            "Zeek is not installed or not in PATH. "
            "Install Zeek or provide pre-generated Zeek logs with --conn, --dns, --ssl."
        )

    tmpdir = output_dir or tempfile.mkdtemp(prefix="beacon_score_zeek_")

    cmd = [
        _zeek_bin(),
        "-r", os.path.abspath(pcap_path),
        "LogAscii::use_json=T",
    ] + ZEEK_SCRIPTS

    result = subprocess.run(
        cmd,
        cwd=tmpdir,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        stderr = result.stderr[:500] if result.stderr else "(no stderr)"
        raise RuntimeError(f"Zeek exited with code {result.returncode}: {stderr}")

    def find_log(name: str) -> str:
        candidates = [
            os.path.join(tmpdir, f"{name}.log"),
            os.path.join(tmpdir, f"{name}.log.gz"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return ""

    return {
        "conn":   find_log("conn"),
        "dns":    find_log("dns"),
        "ssl":    find_log("ssl"),
        "tmpdir": tmpdir,
        "zeek_stdout": result.stdout,
        "zeek_stderr": result.stderr,
    }


def cleanup_tmpdir(tmpdir: str):
    if tmpdir and os.path.exists(tmpdir):
        shutil.rmtree(tmpdir, ignore_errors=True)
