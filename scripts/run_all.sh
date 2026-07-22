#!/usr/bin/env bash
# End-to-end orchestrator for Linux OSHA (assumes Hadoop/Pig/Hive/HBase on PATH).
# Usage from repo root:
#   source config.env
#   bash scripts/run_all.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f config.env ]]; then
  # shellcheck disable=SC1091
  source config.env
fi

: "${HDFS_PARSED:=/data/security/parsed}"
: "${HDFS_LOGS:=/data/security/logs}"
: "${THRESHOLD:=50}"

echo "======== 1/5 HDFS ingest ========"
bash scripts/01_hdfs_ingest.sh

echo "======== 2/5 Pig parse ========"
hdfs dfs -rm -r -f "$HDFS_PARSED" || true
pig -f scripts/02_pig_parse.pig \
  -param "INPUT_GLOB=${HDFS_LOGS}/*/*/*/access.log" \
  -param "OUTPUT=${HDFS_PARSED}"

echo "======== 3/5 MapReduce ========"
bash scripts/03_run_mapreduce.sh

echo "======== 4/5 Hive ========"
hive -f scripts/04_hive.hql

echo "======== 5/5 HBase + incident ========"
bash scripts/05_hbase_blacklist.sh
python3 scripts/06_export_incident.py --threshold "$THRESHOLD"

echo "All stages complete."
