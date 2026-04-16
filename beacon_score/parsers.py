"""
Zeek log parsers. Handles both classic TSV (#fields/#types header) and
JSON-per-line formats. Auto-detects format on open.
"""

import json
import gzip
import os
from pathlib import Path
from typing import Iterator


def _open_log(path: str):
    p = Path(path)
    if p.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _is_json_log(path: str) -> bool:
    with _open_log(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            return line.startswith("{")
    return False


def _parse_tsv_log(path: str) -> Iterator[dict]:
    fields = []
    types = []
    with _open_log(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#types"):
                types = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                parts = line.split("\t")
                row = {}
                for i, field in enumerate(fields):
                    val = parts[i] if i < len(parts) else "-"
                    if val == "-" or val == "(empty)":
                        row[field] = None
                    else:
                        t = types[i] if i < len(types) else "string"
                        try:
                            if t in ("double", "interval", "time"):
                                row[field] = float(val)
                            elif t in ("count", "int", "port"):
                                row[field] = int(val)
                            elif t == "bool":
                                row[field] = val == "T"
                            else:
                                row[field] = val
                        except (ValueError, TypeError):
                            row[field] = val
                yield row


def _parse_json_log(path: str) -> Iterator[dict]:
    with _open_log(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse_log(path: str) -> Iterator[dict]:
    if not os.path.exists(path):
        return
    if _is_json_log(path):
        yield from _parse_json_log(path)
    else:
        yield from _parse_tsv_log(path)


def load_conn_log(path: str) -> list[dict]:
    records = []
    for row in parse_log(path):
        if not row.get("id.resp_h"):
            continue
        records.append({
            "ts":           row.get("ts", 0),
            "uid":          row.get("uid", ""),
            "id.orig_h":    row.get("id.orig_h", ""),
            "id.orig_p":    row.get("id.orig_p", 0),
            "id.resp_h":    row.get("id.resp_h", ""),
            "id.resp_p":    row.get("id.resp_p", 0),
            "proto":        row.get("proto", ""),
            "service":      row.get("service", ""),
            "duration":     row.get("duration"),
            "orig_bytes":   row.get("orig_bytes"),
            "resp_bytes":   row.get("resp_bytes"),
            "conn_state":   row.get("conn_state", ""),
            "orig_pkts":    row.get("orig_pkts"),
            "resp_pkts":    row.get("resp_pkts"),
        })
    return records


def load_dns_log(path: str) -> list[dict]:
    records = []
    for row in parse_log(path):
        answers = row.get("answers", [])
        # TSV format delivers answers as comma-separated string, JSON as list.
        # Normalize to list in both cases.
        if isinstance(answers, str):
            answers = [a.strip() for a in answers.split(",") if a.strip()] if answers else []
        ttls = row.get("TTLs", [])
        if isinstance(ttls, str):
            parsed_ttls = []
            for t in ttls.split(","):
                t = t.strip()
                if t:
                    try:
                        parsed_ttls.append(float(t))
                    except ValueError:
                        pass
            ttls = parsed_ttls
        records.append({
            "ts":       row.get("ts", 0),
            "uid":      row.get("uid", ""),
            "id.orig_h":row.get("id.orig_h", ""),
            "id.resp_h":row.get("id.resp_h", ""),
            "query":    row.get("query", ""),
            "qtype":    row.get("qtype_name", row.get("qtype", "")),
            "answers":  answers,
            "TTLs":     ttls,
            "rcode":    row.get("rcode_name", ""),
        })
    return records


def load_ssl_log(path: str) -> list[dict]:
    records = []
    for row in parse_log(path):
        records.append({
            "ts":               row.get("ts", 0),
            "uid":              row.get("uid", ""),
            "id.orig_h":        row.get("id.orig_h", ""),
            "id.resp_h":        row.get("id.resp_h", ""),
            "id.resp_p":        row.get("id.resp_p", 443),
            "version":          row.get("version", ""),
            "cipher":           row.get("cipher", ""),
            "curve":            row.get("curve", ""),
            "server_name":      row.get("server_name", ""),
            "subject":          row.get("subject", ""),
            "issuer":           row.get("issuer", ""),
            "not_valid_before": row.get("not_valid_before", ""),
            "not_valid_after":  row.get("not_valid_after", ""),
            "ja3":              row.get("ja3", ""),
            "ja3s":             row.get("ja3s", ""),
            "validation_status":row.get("validation_status", ""),
        })
    return records
