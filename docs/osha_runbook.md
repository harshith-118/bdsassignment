# OSHA Linux runbook — Group 13

Lab OS: **Linux**. All commands are bash. Run from the unzipped project root.

## Prerequisites on lab

- Hadoop 3.x (`hdfs`, `hadoop`) on PATH  
- Pig, Hive, HBase shells  
- Java 8/11; Maven optional if JAR is already in `mapreduce/target/`  
- Python 3 (incident CSV only)

## One-time setup

```bash
cd GROUP_13_Code   # or whatever folder you unzipped
source config.env
chmod +x scripts/*.sh tools/generate_logs.py scripts/06_export_incident.py
```

If you need to regenerate sample data on the lab machine:

```bash
python3 tools/generate_logs.py --out data/sample --days 7 --seed 13
```

## Full pipeline

```bash
source config.env
bash scripts/run_all.sh
```

Or step-by-step (better for screenshots):

### 1. HDFS ingest (M1)

```bash
bash scripts/01_hdfs_ingest.sh
hdfs dfs -ls -R /data/security/logs
```

### 2. Pig parse (M1)

```bash
hdfs dfs -rm -r -f /data/security/parsed
pig -f scripts/02_pig_parse.pig \
  -param INPUT_GLOB=/data/security/logs/*/*/*/access.log \
  -param OUTPUT=/data/security/parsed
hdfs dfs -cat /data/security/parsed/part-* | head -20
```

### 3. MapReduce (M2)

```bash
bash scripts/03_run_mapreduce.sh
# or:
# hadoop jar mapreduce/target/suspicious-ip-detection-1.0.jar \
#   edu.bits.bds.security.SuspiciousIpDriver \
#   /data/security/parsed /data/security/agg/ip_hour 50
hdfs dfs -cat /data/security/agg/ip_hour/part-* | awk -F'\t' '$6==1' | head
```

### 4. Hive (M3)

```bash
hive -f scripts/04_hive.hql
# Screenshot: SHOW TABLES; SELECT * FROM v_flagged_week_summary; top10 query output
```

### 5. HBase + incident (M3)

```bash
bash scripts/05_hbase_blacklist.sh
python3 scripts/06_export_incident.py
```

Copy `report/top10_suspicious_ips.csv` and `report/incident_report.md` into the PDF.

## Rebuild JAR on lab (if needed)

```bash
cd mapreduce
mvn -DskipTests package
cd ..
```

## Submission names

- `GROUP_13.pdf`
- `GROUP_13_Code.zip`
