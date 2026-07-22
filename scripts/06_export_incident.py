#!/usr/bin/env python3
"""
M3 — Build CSV + incident report from top-10 TSV (local or HDFS-merged).
Usage:
  python3 scripts/06_export_incident.py [--input report/top10_from_hdfs.tsv]
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

HEADERS = [
    "ip",
    "peak_hour",
    "peak_errors",
    "total_violations",
    "endpoint_diversity",
    "threat_level",
    "reason",
]


def load_rows(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            rows.append(dict(zip(HEADERS, parts[:7])))
    return rows


def write_csv(rows: list[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADERS)
        w.writeheader()
        w.writerows(rows)


def write_incident(rows: list[dict], out: Path, threshold: int) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Incident Report — Server Log Security Threat Detection",
        "",
        f"**Group:** 13  ",
        f"**Generated:** {now}  ",
        f"**Detection rule:** IP with more than {threshold} HTTP 4xx+5xx responses in any single hour is flagged (`HIGH_ERROR_RATE`).",
        "",
        "## Summary",
        "",
        f"This report lists the **top {len(rows)}** suspicious source IPs identified from Apache Combined access logs "
        "via the Hadoop pipeline (HDFS → Pig → MapReduce → Hive → HBase).",
        "",
        "## Top suspicious IPs",
        "",
        "| IP | Peak hour | Peak errors | Total violations | Endpoints | Threat | Reason |",
        "|----|-----------|-------------|------------------|-----------|--------|--------|",
    ]
    for r in rows:
        lines.append(
            f"| {r['ip']} | {r['peak_hour']} | {r['peak_errors']} | "
            f"{r['total_violations']} | {r['endpoint_diversity']} | "
            f"{r['threat_level']} | {r['reason']} |"
        )
    lines.extend(
        [
            "",
            "## Recommended actions",
            "",
            "1. **High** threat IPs — block or rate-limit at the edge; confirm in HBase blacklist.",
            "2. **Medium** threat IPs — elevate monitoring; retain in blacklist until TTL expiry (7 days).",
            "3. Review `/login`, `/admin`, and scan-like paths for hardening (WAF rules, fail2ban, MFA).",
            "4. Re-run the pipeline daily; HBase CF TTL auto-expires stale blacklist rows.",
            "",
            "## Pipeline evidence",
            "",
            "- HDFS date-partitioned raw logs under `/data/security/logs/`",
            "- Pig-parsed fields under `/data/security/parsed/`",
            "- MapReduce IP-hour aggregates under `/data/security/agg/ip_hour/`",
            "- Hive views `v_flagged_week_summary`, `v_flagged_endpoints`",
            "- HBase table `security_ip_blacklist` (CF `info`, TTL 604800s)",
            "",
        ]
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="report/top10_from_hdfs.tsv")
    p.add_argument("--csv", default="report/top10_suspicious_ips.csv")
    p.add_argument("--incident", default="report/incident_report.md")
    p.add_argument("--threshold", type=int, default=50)
    args = p.parse_args()

    src = Path(args.input)
    if not src.exists():
        raise SystemExit(
            f"Missing {src}. Run Hive export + scripts/05_hbase_blacklist.sh "
            "(getmerge) or place a TSV manually."
        )
    rows = load_rows(src)
    if not rows:
        raise SystemExit(f"No data rows in {src}")
    write_csv(rows, Path(args.csv))
    write_incident(rows, Path(args.incident), args.threshold)
    print(f"Wrote {args.csv} ({len(rows)} rows)")
    print(f"Wrote {args.incident}")


if __name__ == "__main__":
    main()
