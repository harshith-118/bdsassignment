#!/usr/bin/env python3
"""
Offline dry-run of Pig-like parse + MR aggregation (no Hadoop required).
Validates planted IPs flag under the default threshold.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

LINE_RE = re.compile(
    r'^(?P<ip>\S+) .*\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}).* '
    r'"(?P<method>\w+)\s+(?P<endpoint>\S+)\s+HTTP/[^"]*"\s+(?P<status>\d{3})\s+'
)
MON = {m: f"{i:02d}" for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def hour_bucket(ts: str) -> str:
    # dd/MMM/yyyy:HH:mm:ss
    dd, rest = ts.split("/", 1)
    mon, rest = rest.split("/", 1)
    yyyy, hms = rest.split(":", 1)
    HH = hms[:2]
    return f"{yyyy}-{MON[mon]}-{dd}-{HH}"


def main() -> None:
    threshold = 50
    root = Path("data/sample")
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    for path in sorted(root.rglob("access.log")):
        try:
            int(path.parts[-4])
            int(path.parts[-3])
            int(path.parts[-2])
        except (ValueError, IndexError):
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            m = LINE_RE.search(line)
            if not m:
                continue
            status = int(m.group("status"))
            if status < 400:
                continue
            key = (m.group("ip"), hour_bucket(m.group("ts")))
            if status <= 499:
                counts[key][0] += 1
            else:
                counts[key][1] += 1

    flagged = []
    for (ip, hb), (c4, c5) in counts.items():
        total = c4 + c5
        if total > threshold:
            flagged.append((ip, hb, c4, c5, total))

    planted = json.loads(Path("data/planted_ips.json").read_text(encoding="utf-8"))
    flagged_ips = {r[0] for r in flagged}
    missing = set(planted) - flagged_ips
    print(f"Flagged IP-hours: {len(flagged)}")
    for row in sorted(flagged, key=lambda x: -x[4]):
        print(f"  {row[0]}\t{row[1]}\t4xx={row[2]}\t5xx={row[3]}\ttotal={row[4]}")
    if missing:
        raise SystemExit(f"FAIL: planted IPs not flagged: {sorted(missing)}")
    print("OK: all planted IPs flagged.")


if __name__ == "__main__":
    main()
