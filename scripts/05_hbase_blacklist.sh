#!/usr/bin/env bash
# M3 — Create HBase blacklist with CF TTL and load top-10 suspicious IPs.
# Usage (Linux OSHA):
#   source config.env
#   bash scripts/05_hbase_blacklist.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f config.env ]]; then
  # shellcheck disable=SC1091
  source config.env
fi

: "${HBASE_TABLE:=security_ip_blacklist}"
: "${HBASE_TTL_SECONDS:=604800}"
: "${HDFS_EXPORT:=/data/security/export}"

EXPORT_DIR="${HDFS_EXPORT}/top10_suspicious"
LOCAL_TOP10="./report/top10_from_hdfs.tsv"

echo "==> Fetching top-10 export from HDFS"
mkdir -p report
rm -f "$LOCAL_TOP10"
hdfs dfs -getmerge "$EXPORT_DIR" "$LOCAL_TOP10"

if [[ ! -s "$LOCAL_TOP10" ]]; then
  echo "ERROR: empty export at $EXPORT_DIR — run Hive script first" >&2
  exit 1
fi

echo "==> Drop table if it exists (ignore errors on first run)"
hbase shell -n <<EOF || true
disable '${HBASE_TABLE}'
drop '${HBASE_TABLE}'
EOF

echo "==> Create table with TTL=${HBASE_TTL_SECONDS}s on CF info (screenshot describe)"
hbase shell -n <<EOF
create '${HBASE_TABLE}', {NAME => 'info', VERSIONS => 1, TTL => ${HBASE_TTL_SECONDS}}
describe '${HBASE_TABLE}'
EOF

echo "==> Loading top-10 rows via put"
PUTS_FILE="./report/hbase_puts.tmp"
{
  while IFS=$'\t' read -r ip peak_hour peak_errors total_violations endpoint_diversity threat_level reason; do
    [[ -z "${ip:-}" ]] && continue
    printf "put '%s', '%s', 'info:first_seen', '%s'\n" "$HBASE_TABLE" "$ip" "$peak_hour"
    printf "put '%s', '%s', 'info:last_seen', '%s'\n" "$HBASE_TABLE" "$ip" "$peak_hour"
    printf "put '%s', '%s', 'info:violation_count', '%s'\n" "$HBASE_TABLE" "$ip" "$total_violations"
    printf "put '%s', '%s', 'info:reason', '%s'\n" "$HBASE_TABLE" "$ip" "$reason"
    printf "put '%s', '%s', 'info:threat_level', '%s'\n" "$HBASE_TABLE" "$ip" "$threat_level"
  done < "$LOCAL_TOP10"
} > "$PUTS_FILE"

hbase shell -n "$PUTS_FILE"

echo "==> Scan blacklist (screenshot this)"
hbase shell -n <<EOF
scan '${HBASE_TABLE}'
EOF

echo "Done. Table=${HBASE_TABLE}"
