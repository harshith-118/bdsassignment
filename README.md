# GROUP 13 — Server Log Security Threat Detection

Big Data Systems (DSECLZG522) **graded group assignment** (Problem 13).  
Detect suspicious IPs from Apache Combined access logs using **HDFS + Pig + Java MapReduce + Hive + HBase**.

Submission artifacts (Taxila only, by 6 Aug 2026):

- `GROUP_13.pdf` — report with OSHA screenshots, contribution table, CSV/incident appendix  
- `GROUP_13_Code.zip` — this project (sources, sample data, scripts, JAR)

## Requirements coverage

| Required task | Location |
|---------------|----------|
| HDFS date-partition ingest | `scripts/01_hdfs_ingest.sh` |
| Pig parse (IP, ts, method, URL, status) | `scripts/02_pig_parse.pig` |
| Java MR: 4xx/5xx per IP-hour, flag > 50 | `mapreduce/src/main/java/...` |
| Hive external tables + historical queries | `scripts/04_hive.hql` |
| HBase blacklist + TTL + top-IP load | `scripts/05_hbase_blacklist.sh` |
| CSV + incident report | `scripts/06_export_incident.py`, `report/` |

Full report draft (convert to PDF after screenshots): `report/GROUP_13_Report_DRAFT.md`  
Graded checklist: `docs/ASSIGNMENT_CHECKLIST.md`  
OSHA Linux steps: `docs/osha_runbook.md`  
Schemas: `docs/schemas.md`

## Run on OSHA (Linux)

```bash
source config.env
chmod +x scripts/*.sh
cd mapreduce && mvn -DskipTests package && cd ..
bash scripts/run_all.sh
python3 scripts/06_export_incident.py
```

Then capture every screenshot listed in `docs/screenshot_checklist.md`, fill names in the contribution table, export `GROUP_13.pdf`, and pack code:

```bash
bash scripts/pack_code_zip.sh
```

## Offline preparation (before lab)

```bash
python3 tools/generate_logs.py --out data/sample --days 7 --seed 13
python3 tools/offline_validate.py
```

Sample logs are already under `data/sample/`. Planted attackers: `data/planted_ips.json`.

## Layout

| Path | Package | Role |
|------|---------|------|
| `tools/generate_logs.py` | M1 | Dataset |
| `scripts/01_hdfs_ingest.sh` | M1 | HDFS ingest |
| `scripts/02_pig_parse.pig` | M1 | Pig parser |
| `mapreduce/` | M2 | Java MapReduce |
| `scripts/03_run_mapreduce.sh` | M2 | MR runner |
| `scripts/04_hive.hql` | M3 | Hive |
| `scripts/05_hbase_blacklist.sh` | M3 | HBase |
| `scripts/06_export_incident.py` | M3 | CSV / incident |
| `report/GROUP_13_Report_DRAFT.md` | — | PDF source draft |
