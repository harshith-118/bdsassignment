# Data contracts — Group 13 Server Log Security Threat Detection

All stages use **tab-separated** text, **no header row**.
Timezone for timestamps: fixed offset `+0000` (UTC). Hour bucket uses the same clock.

## 1. Raw Apache Combined Log (HDFS ingest)

Path: `/data/security/logs/yyyy/MM/dd/access.log`

Format:
```
IP - - [dd/MMM/yyyy:HH:mm:ss +0000] "METHOD /endpoint HTTP/1.1" status size "referer" "user-agent"
```

## 2. Pig → parsed TSV

Path: `/data/security/parsed/yyyy-MM-dd/`

| # | Column       | Example              |
|---|--------------|----------------------|
| 1 | ip           | 203.0.113.10         |
| 2 | ts           | 15/Jul/2026:14:03:22 |
| 3 | hour_bucket  | 2026-07-15-14        |
| 4 | method       | GET                  |
| 5 | endpoint     | /login               |
| 6 | status       | 401                  |
| 7 | user_agent   | Mozilla/5.0          |

Unparseable lines are dropped (FILTER).

## 3. MapReduce → aggregation TSV

Path: `/data/security/agg/ip_hour/`

| # | Column         | Example           |
|---|----------------|-------------------|
| 1 | ip             | 203.0.113.10      |
| 2 | hour_bucket    | 2026-07-15-14     |
| 3 | count_4xx      | 62                |
| 4 | count_5xx      | 3                 |
| 5 | error_count    | 65                |
| 6 | is_suspicious  | 1                 |
| 7 | reason         | HIGH_ERROR_RATE   |

- Mapper counts only HTTP status 400–599.
- `is_suspicious = 1` iff `error_count > THRESHOLD` (default 50); else `0` and reason `-`.

## 4. Hive export → top 10

Path: `/data/security/export/top10_suspicious.tsv`

Suggested columns (from Hive query):
`ip, peak_hour, peak_errors, total_violations, endpoint_diversity, threat_level, reason`

## 5. HBase `security_ip_blacklist`

- Row key: IP
- CF `info` with TTL = 604800 seconds (7 days)
- Qualifiers: `first_seen`, `last_seen`, `violation_count`, `reason`, `threat_level`
