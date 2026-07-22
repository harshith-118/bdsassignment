#!/usr/bin/env python3
"""
Generate seeded synthetic Apache Combined Log files for Problem 13.
Produces day-partitioned access.log files plus planted_ips.json.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

BENIGN_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12",
    "10.0.0.5", "10.0.0.8", "10.0.1.20",
    "172.16.0.4", "172.16.0.9", "8.8.8.8", "1.1.1.1",
]

BENIGN_PATHS = [
    "/", "/index.html", "/about", "/products", "/products/1",
    "/products/2", "/cart", "/search", "/api/health", "/static/app.js",
    "/static/style.css", "/images/logo.png", "/contact", "/blog",
]

SCAN_PATHS = [
    "/admin", "/admin/login", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/.env", "/.git/config", "/actuator/health", "/api/v1/users",
    "/login", "/manager/html", "/console", "/solr/admin", "/server-status",
] + [f"/scan/{i}" for i in range(80)]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "curl/8.0.1",
    "python-requests/2.31.0",
]

# Planted attackers — must exceed threshold (>50 errors in one hour)
PLANTED = {
    "203.0.113.10": {
        "role": "brute_force",
        "threat_level": "High",
        "reason": "HIGH_ERROR_RATE",
        "note": "Many 401/403 against /login and /admin in a single hour",
    },
    "198.51.100.66": {
        "role": "scanner",
        "threat_level": "High",
        "reason": "HIGH_ERROR_RATE",
        "note": "Wide 404 scanning across many endpoints in a single hour",
    },
    "203.0.113.77": {
        "role": "server_error_burst",
        "threat_level": "Medium",
        "reason": "HIGH_ERROR_RATE",
        "note": "Burst of 500/502 responses in a single hour",
    },
    "198.51.100.20": {
        "role": "mixed_abuse",
        "threat_level": "High",
        "reason": "HIGH_ERROR_RATE",
        "note": "Mixed 4xx/5xx abuse across two busy hours",
    },
}


def fmt_ts(dt: datetime) -> str:
    return f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def log_line(ip: str, dt: datetime, method: str, path: str, status: int,
             size: int, ua: str, referer: str = "-") -> str:
    return (
        f'{ip} - - [{fmt_ts(dt)}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "{referer}" "{ua}"'
    )


def random_dt(day: datetime, rng: random.Random, hour: int | None = None) -> datetime:
    h = hour if hour is not None else rng.randint(0, 23)
    return day.replace(hour=h, minute=rng.randint(0, 59), second=rng.randint(0, 59))


def gen_benign(day: datetime, rng: random.Random, n: int) -> list[str]:
    lines = []
    for _ in range(n):
        ip = rng.choice(BENIGN_IPS)
        path = rng.choice(BENIGN_PATHS)
        method = rng.choice(["GET", "GET", "GET", "POST", "HEAD"])
        # Mostly 200; occasional soft errors below threshold
        roll = rng.random()
        if roll < 0.92:
            status = 200
        elif roll < 0.96:
            status = 304
        elif roll < 0.985:
            status = 404
        else:
            status = 500
        size = rng.randint(200, 50000) if status == 200 else rng.randint(0, 800)
        lines.append(log_line(ip, random_dt(day, rng), method, path, status, size,
                              rng.choice(USER_AGENTS)))
    return lines


def inject_brute_force(day: datetime, rng: random.Random) -> list[str]:
    """203.0.113.10 — 70 x 401/403 in hour 14."""
    ip = "203.0.113.10"
    lines = []
    hour = 14
    for i in range(70):
        path = "/login" if i % 2 == 0 else "/admin"
        status = 401 if i % 3 else 403
        dt = day.replace(hour=hour, minute=i % 60, second=rng.randint(0, 59))
        lines.append(log_line(ip, dt, "POST", path, status, 256, USER_AGENTS[-1]))
    # a few successes so it looks real
    for _ in range(5):
        lines.append(log_line(ip, random_dt(day, rng, 14), "GET", "/", 200, 1200,
                              USER_AGENTS[0]))
    return lines


def inject_scanner(day: datetime, rng: random.Random) -> list[str]:
    """198.51.100.66 — 80 x 404 across many paths in hour 10."""
    ip = "198.51.100.66"
    lines = []
    hour = 10
    for i, path in enumerate(SCAN_PATHS[:80]):
        dt = day.replace(hour=hour, minute=i % 60, second=rng.randint(0, 59))
        lines.append(log_line(ip, dt, "GET", path, 404, 180, "nikto/2.1.6"))
    return lines


def inject_5xx_burst(day: datetime, rng: random.Random) -> list[str]:
    """203.0.113.77 — 55 x 500/502 in hour 18."""
    ip = "203.0.113.77"
    lines = []
    hour = 18
    for i in range(55):
        status = 500 if i % 2 == 0 else 502
        path = rng.choice(["/api/orders", "/api/checkout", "/api/pay"])
        dt = day.replace(hour=hour, minute=i % 60, second=rng.randint(0, 59))
        lines.append(log_line(ip, dt, "POST", path, status, 512, USER_AGENTS[2]))
    return lines


def inject_mixed(day: datetime, rng: random.Random) -> list[str]:
    """198.51.100.20 — 55 errors hour 9 + 60 errors hour 15."""
    ip = "198.51.100.20"
    lines = []
    for hour, n in ((9, 55), (15, 60)):
        for i in range(n):
            if i % 4 == 0:
                status, path, method = 500, "/api/unstable", "GET"
            else:
                status = 401 if i % 2 else 404
                path = "/login" if status == 401 else f"/hidden/{i}"
                method = "POST" if status == 401 else "GET"
            dt = day.replace(hour=hour, minute=i % 60, second=rng.randint(0, 59))
            lines.append(log_line(ip, dt, method, path, status, 300, USER_AGENTS[-2]))
    return lines


def write_day(out_root: Path, day: datetime, lines: list[str]) -> Path:
    # HDFS-style yyyy/MM/dd only (used by ingest script)
    hdfs_style = out_root / f"{day.year:04d}" / f"{day.month:02d}" / f"{day.day:02d}"
    hdfs_style.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines) + "\n"
    (hdfs_style / "access.log").write_text(content, encoding="utf-8")
    return hdfs_style / "access.log"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic Apache Combined logs")
    parser.add_argument("--out", default="data/sample", help="Output directory")
    parser.add_argument("--days", type=int, default=7, help="Number of days")
    parser.add_argument("--seed", type=int, default=13, help="RNG seed")
    parser.add_argument("--benign-per-day", type=int, default=800)
    parser.add_argument("--start", default="2026-07-15", help="Start date YYYY-MM-DD")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    start = datetime.strptime(args.start, "%Y-%m-%d")
    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)

    # Clear previous day folders under out (keep structure clean)
    for child in list(out_root.iterdir()):
        if child.is_dir():
            import shutil
            shutil.rmtree(child)

    attack_day_index = 2  # inject heavy attacks on day 3 (and light echoes nearby)

    for d in range(args.days):
        day = start + timedelta(days=d)
        lines = gen_benign(day, rng, args.benign_per_day)
        if d == attack_day_index:
            lines.extend(inject_brute_force(day, rng))
            lines.extend(inject_scanner(day, rng))
            lines.extend(inject_5xx_burst(day, rng))
            lines.extend(inject_mixed(day, rng))
        elif d in (attack_day_index - 1, attack_day_index + 1):
            # lighter echoes so Hive "week" views have history
            lines.extend(inject_brute_force(day, rng)[:20])
            lines.extend(inject_scanner(day, rng)[:15])
        rng.shuffle(lines)
        path = write_day(out_root, day, lines)
        print(f"Wrote {len(lines)} lines -> {path}")

    planted_path = Path("data/planted_ips.json")
    planted_path.parent.mkdir(parents=True, exist_ok=True)
    planted_path.write_text(json.dumps(PLANTED, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {planted_path}")
    print("Done. Attack peak day:", (start + timedelta(days=attack_day_index)).date())


if __name__ == "__main__":
    main()
