#!/usr/bin/env bash
# Build /data/security/export/top10_suspicious from MapReduce flagged rows.
# Use when Hive INSERT OVERWRITE DIRECTORY fails on OSHA.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
[[ -f config.env ]] && source config.env

: "${HDFS_AGG:=/data/security/agg/ip_hour}"
: "${HDFS_EXPORT:=/data/security/export}"

EXPORT_DIR="${HDFS_EXPORT}/top10_suspicious"
LOCAL_TSV="./report/top10_from_hdfs.tsv"
mkdir -p report

echo "==> Building top-10 from MR agg: $HDFS_AGG"
# Aggregate per IP: peak hour, peak errors, total violations
hdfs dfs -cat "${HDFS_AGG}/part-"* \
  | awk -F'\t' '$6==1 {
      ip=$1; hour=$2; err=$5+0; reason=$7;
      total[ip]+=err;
      if (err >= peak[ip]) { peak[ip]=err; phour[ip]=hour; preason[ip]=reason; }
    }
    END {
      for (ip in total) {
        tl = (peak[ip] >= 100 || total[ip] >= 200) ? "High" : "Medium";
        printf "%s\t%s\t%d\t%d\t%d\t%s\t%s\n", ip, phour[ip], peak[ip], total[ip], 0, tl, preason[ip];
      }
    }' \
  | sort -t$'\t' -k4,4nr \
  | head -10 > "$LOCAL_TSV"

if [[ ! -s "$LOCAL_TSV" ]]; then
  echo "ERROR: no suspicious rows found in $HDFS_AGG" >&2
  exit 1
fi

echo "==> Local top-10:"
cat "$LOCAL_TSV"

echo "==> Putting to HDFS $EXPORT_DIR"
hdfs dfs -rm -r -f "$EXPORT_DIR" || true
hdfs dfs -mkdir -p "$EXPORT_DIR"
hdfs dfs -put -f "$LOCAL_TSV" "$EXPORT_DIR/top10.tsv"
hdfs dfs -ls -R "$EXPORT_DIR"
echo "Done. Next: bash scripts/05_hbase_blacklist.sh"
