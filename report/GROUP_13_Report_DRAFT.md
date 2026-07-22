# Big Data Systems (DSECLZG522) — Group Project Report

**Assignment:** Problem 13 — Server Log Security Threat Detection  
**Group Number:** 13  
**Submission files:** `GROUP_13.pdf`, `GROUP_13_Code.zip`  
**Platform:** OSHA Lab (Linux)  
**Deadline:** 6 August 2026  

---

## 1. Group details and contribution

| Sl. No. | Name (as in Canvas) | ID NO | Contribution |
|--------:|---------------------|-------|--------------|
| 1 | _fill_ | _fill_ | **M1:** Synthetic Apache Combined dataset generation; HDFS date-partitioned ingestion (`/data/security/logs/yyyy/MM/dd`); Pig Latin parsing to extract IP, timestamp, method, endpoint, status, user-agent into contracted TSV |
| 2 | _fill_ | _fill_ | **M2:** Java MapReduce (Mapper, Reducer, Driver) to count 4xx and 5xx per IP per hour; flag IPs with error_count > 50; Maven packaging and `hadoop jar` execution scripts |
| 3 | _fill_ | _fill_ | **M3:** Hive external tables and analytical views; HBase blacklist table with CF TTL; bulk load of top suspicious IPs; CSV and incident report; report assembly and screenshots |

> Members with “No Contribution” receive no marks. Replace `_fill_` before PDF export.

---

## 2. Problem statement (summary)

Given raw Apache HTTP server logs, perform security analytics to detect threats such as brute-force attempts and network scanning. The solution must use **HDFS, MapReduce, Pig, Hive, and HBase** to ingest, process, analyze, and store findings, and must produce a CSV plus an incident summary of the top suspicious IPs.

---

## 3. Objectives achieved

| Objective | How addressed |
|-----------|----------------|
| Analyze server logs for anomalous activity | Seeded Combined logs with brute-force (401/403), scanning (404), and 5xx bursts |
| Detect suspicious IPs by failed-request thresholds | Java MR flags IP-hour rows where `4xx+5xx > 50` |
| Use full Hadoop ecosystem | HDFS → Pig → Java MapReduce → Hive → HBase (see §5–§9) |
| Blacklist with TTL | HBase CF `info` TTL = 604800 seconds (7 days) |
| Incident deliverables | `report/top10_suspicious_ips.csv` and incident narrative (§10) |

---

## 4. Dataset

- **Format:** Apache Combined Log Format  
- **Source:** Deterministic synthetic generator (`tools/generate_logs.py`, seed `13`)  
- **Volume:** 7 days (`2026-07-15` … `2026-07-21`), day-partitioned under `data/sample/yyyy/MM/dd/access.log`  
- **Planted threat IPs** (must appear in flagged output):

| IP | Role | Expected signal |
|----|------|-----------------|
| `203.0.113.10` | Brute-force | ≥70 × 401/403 on `/login`, `/admin` in one hour |
| `198.51.100.66` | Scanner | ≥80 × 404 across many paths in one hour |
| `203.0.113.77` | Server-error burst | ≥55 × 500/502 in one hour |
| `198.51.100.20` | Mixed abuse | Two hours each with >50 errors |

Offline verification (no cluster): `python3 tools/offline_validate.py` confirms all planted IPs exceed the threshold.

---

## 5. HDFS ingestion

**Task:** Load raw logs into HDFS organized by date; verify with `hdfs dfs -ls`.

**Implementation:** `scripts/01_hdfs_ingest.sh`  
**Target path:** `/data/security/logs/yyyy/MM/dd/access.log`

**Commands (OSHA Linux):**
```bash
source config.env
bash scripts/01_hdfs_ingest.sh
hdfs dfs -ls -R /data/security/logs
```

**Evidence — Screenshot 1:** HDFS recursive listing showing date partitions.  
_[Paste OSHA screenshot here]_

---

## 6. Pig parsing

**Task:** Parse raw logs; extract IP, timestamp, endpoint, method, response code (and user-agent).

**Implementation:** `scripts/02_pig_parse.pig`  
**Output:** `/data/security/parsed/` — TSV  
`ip, ts, hour_bucket, method, endpoint, status, user_agent`  
(`hour_bucket` = `yyyy-MM-dd-HH`)

**Commands:**
```bash
hdfs dfs -rm -r -f /data/security/parsed
pig -f scripts/02_pig_parse.pig \
  -param INPUT_GLOB=/data/security/logs/*/*/*/access.log \
  -param OUTPUT=/data/security/parsed
hdfs dfs -cat /data/security/parsed/part-* | head -20
```

**Evidence — Screenshot 2:** Pig job success.  
**Evidence — Screenshot 3:** Sample parsed rows.  
_[Paste OSHA screenshots here]_

---

## 7. MapReduce (Java)

**Task:** Aggregate counts of 4xx and 5xx per IP per hour; flag IPs exceeding the threshold (more than 50 failed attempts in an hour).

**Implementation (OpenJDK 8/11):**
- `ErrorCountMapper.java` — emits `ip\thour_bucket` → `4xx` or `5xx`
- `ErrorCountReducer.java` — sums counts; sets `is_suspicious=1` when `error_count > threshold`
- `SuspiciousIpDriver.java` — job driver; threshold CLI argument (default **50**)

**Output TSV** (`/data/security/agg/ip_hour/`):  
`ip, hour_bucket, count_4xx, count_5xx, error_count, is_suspicious, reason`

**Commands:**
```bash
cd mapreduce && mvn -DskipTests package && cd ..
bash scripts/03_run_mapreduce.sh
hdfs dfs -cat /data/security/agg/ip_hour/part-* | awk -F'\t' '$6==1' | head
```

**Evidence — Screenshot 4:** MapReduce / YARN job log (counters).  
**Evidence — Screenshot 5:** Flagged suspicious IP-hour rows.  
_[Paste OSHA screenshots here]_

---

## 8. Hive analysis

**Task:** External tables on parsed and aggregated data; queries/views for historical flagged-IP behavior (violations over the loaded window, endpoint variety); identify top suspicious IPs.

**Implementation:** `scripts/04_hive.hql`  
- DB: `security_analytics`  
- Tables: `ext_parsed_logs`, `ext_ip_hour_agg`  
- Views: `v_flagged_ips`, `v_flagged_week_summary`, `v_flagged_endpoints`  
- Materialized top-N → `/data/security/export/top10_suspicious/`

**Commands:**
```bash
hive -f scripts/04_hive.hql
```

**Evidence — Screenshot 6:** `SHOW TABLES` / `DESCRIBE`.  
**Evidence — Screenshot 7:** `v_flagged_week_summary` results.  
**Evidence — Screenshot 8:** Endpoint diversity and/or `tmp_top10` results.  
_[Paste OSHA screenshots here]_

---

## 9. HBase blacklist

**Task:** Blacklist table with first/last seen, violation count, reason; TTL so old entries expire; load top suspicious IPs.

**Implementation:** `scripts/05_hbase_blacklist.sh`  
- Table: `security_ip_blacklist`  
- CF: `info` with **TTL = 604800** (7 days)  
- Qualifiers: `first_seen`, `last_seen`, `violation_count`, `reason`, `threat_level`  
- Load: scripted `put` for exported top IPs (appropriate for small N; satisfies assignment load requirement)

**Commands:**
```bash
bash scripts/05_hbase_blacklist.sh
```

**Evidence — Screenshot 9:** `describe 'security_ip_blacklist'` (TTL visible).  
**Evidence — Screenshot 10:** `scan 'security_ip_blacklist'`.  
_[Paste OSHA screenshots here]_

---

## 10. Incident report and CSV

**Task:** CSV and incident report summarizing top suspicious IPs, activities, and threat level.

**Files (regenerate on OSHA after Hive/HBase export):**
- `report/top10_suspicious_ips.csv`
- `report/incident_report.md` (include below / paste into PDF)

**Command:**
```bash
python3 scripts/06_export_incident.py
```

### 10.1 CSV columns

`ip, peak_hour, peak_errors, total_violations, endpoint_diversity, threat_level, reason`

### 10.2 Threat-level rule

- **High** if `peak_errors ≥ 100` **or** `total_violations ≥ 200`  
- Otherwise **Medium** for any flagged IP  

### 10.3 Incident summary (replace with OSHA-regenerated values after lab run)

See current draft in `report/incident_report.md`. After the OSHA pipeline run, re-run `06_export_incident.py` and replace this section with the lab-produced CSV/table so figures match screenshots.

**Recommended actions for SOC:**
1. Block or rate-limit **High** threat IPs at the edge; verify presence in HBase.  
2. Monitor **Medium** IPs until CF TTL expiry.  
3. Harden `/login`, `/admin`, and scan-prone paths.  
4. Schedule daily re-runs of the pipeline.

---

## 11. End-to-end execution on OSHA (Linux)

```bash
cd <unzipped_GROUP_13_Code>
source config.env
chmod +x scripts/*.sh
cd mapreduce && mvn -DskipTests package && cd ..
bash scripts/run_all.sh
```

Detailed steps: `docs/osha_runbook.md`.  
Schema contracts: `docs/schemas.md`.

---

## 12. Code inventory (GROUP_13_Code.zip)

| Path | Component |
|------|-----------|
| `tools/generate_logs.py` | Dataset generator |
| `data/sample/` | Input logs (7 days) |
| `scripts/01_hdfs_ingest.sh` | HDFS ingest |
| `scripts/02_pig_parse.pig` | Pig parser |
| `mapreduce/src/.../*.java` | Java MapReduce |
| `mapreduce/pom.xml` | Maven build |
| `scripts/03_run_mapreduce.sh` | MR runner |
| `scripts/04_hive.hql` | Hive DDL/queries |
| `scripts/05_hbase_blacklist.sh` | HBase TTL + load |
| `scripts/06_export_incident.py` | CSV + incident |
| `scripts/run_all.sh` | Orchestration |
| `config.env` | Paths / threshold / TTL |
| `report/` | CSV + incident outputs |

---

## 13. Requirements traceability

| Required task | Satisfied by | Evidence in PDF |
|---------------|--------------|-----------------|
| HDFS ingest by date | `01_hdfs_ingest.sh` | Screenshot 1 |
| Pig field extraction | `02_pig_parse.pig` | Screenshots 2–3 |
| MR 4xx/5xx per IP-hour + threshold | Java MR + threshold 50 | Screenshots 4–5 |
| Hive external tables + historical analysis | `04_hive.hql` | Screenshots 6–8 |
| HBase blacklist + TTL + top IP load | `05_hbase_blacklist.sh` | Screenshots 9–10 |
| CSV + incident report | `06_export_incident.py` | §10 + CSV appendix |
| Contribution table | §1 | Filled names/IDs |

---

## 14. Conclusion

The Group 13 implementation provides a complete Hadoop-ecosystem pipeline for server-log threat detection: distributed storage of dated logs, Pig-based parsing, Java MapReduce threshold detection of abusive IPs, Hive historical analytics, and an HBase blacklist with automatic TTL expiry, supported by CSV and incident documentation for SOC response.

---

## Appendix A — Screenshot checklist

Use `docs/screenshot_checklist.md` while on OSHA. Every row in §13 must have a corresponding image before converting this document to `GROUP_13.pdf`.
