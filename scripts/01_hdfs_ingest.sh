#!/usr/bin/env bash
# M1 — Ingest day-partitioned Apache logs into HDFS.
# Usage (from repo root on OSHA Linux):
#   source config.env
#   bash scripts/01_hdfs_ingest.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f config.env ]]; then
  # shellcheck disable=SC1091
  source config.env
fi

: "${HDFS_LOGS:=/data/security/logs}"
: "${LOCAL_DATA_DIR:=./data/sample}"

if [[ ! -d "$LOCAL_DATA_DIR" ]]; then
  echo "ERROR: LOCAL_DATA_DIR not found: $LOCAL_DATA_DIR" >&2
  exit 1
fi

echo "==> Ensuring HDFS root: $HDFS_LOGS"
hdfs dfs -mkdir -p "$HDFS_LOGS"

# Expect local layout: data/sample/yyyy/MM/dd/access.log
found=0
while IFS= read -r -d '' logfile; do
  # logfile like ./data/sample/2026/07/15/access.log
  rel="${logfile#"$LOCAL_DATA_DIR"/}"
  year="$(echo "$rel" | cut -d/ -f1)"
  month="$(echo "$rel" | cut -d/ -f2)"
  day="$(echo "$rel" | cut -d/ -f3)"
  # skip flat yyyy-MM-dd folders (only numeric yyyy/MM/dd)
  if [[ ! "$year" =~ ^[0-9]{4}$ ]]; then
    continue
  fi
  dest="${HDFS_LOGS}/${year}/${month}/${day}"
  echo "Putting $logfile -> $dest/"
  hdfs dfs -mkdir -p "$dest"
  hdfs dfs -put -f "$logfile" "$dest/access.log"
  found=1
done < <(find "$LOCAL_DATA_DIR" -type f -name 'access.log' -print0)

if [[ "$found" -eq 0 ]]; then
  echo "ERROR: No access.log files under $LOCAL_DATA_DIR/yyyy/MM/dd/" >&2
  exit 1
fi

echo "==> HDFS listing (screenshot this):"
hdfs dfs -ls -R "$HDFS_LOGS"
echo "Done."
