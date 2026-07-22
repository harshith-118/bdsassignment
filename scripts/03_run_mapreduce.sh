#!/usr/bin/env bash
# M2 — Build (optional) and run Java MapReduce suspicious-IP job.
# Usage:
#   source config.env
#   bash scripts/03_run_mapreduce.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f config.env ]]; then
  # shellcheck disable=SC1091
  source config.env
fi

: "${HDFS_PARSED:=/data/security/parsed}"
: "${HDFS_AGG:=/data/security/agg/ip_hour}"
: "${MR_JAR:=./mapreduce/target/suspicious-ip-detection-1.0.jar}"
: "${MR_MAIN:=edu.bits.bds.security.SuspiciousIpDriver}"
: "${THRESHOLD:=50}"

if [[ ! -f "$MR_JAR" ]]; then
  echo "==> JAR missing; building with Maven..."
  (cd mapreduce && mvn -DskipTests package)
fi

if [[ ! -f "$MR_JAR" ]]; then
  echo "ERROR: JAR not found at $MR_JAR" >&2
  exit 1
fi

echo "==> Removing previous MR output (if any): $HDFS_AGG"
hdfs dfs -rm -r -f "$HDFS_AGG" || true

echo "==> Running MapReduce (threshold=$THRESHOLD)"
echo "    input : $HDFS_PARSED"
echo "    output: $HDFS_AGG"
# Do NOT pass main class again — it is already in the JAR manifest.
# Passing it makes some Hadoop versions treat it as args[0] and breaks threshold parsing.
hadoop jar "$MR_JAR" "$HDFS_PARSED" "$HDFS_AGG" "$THRESHOLD"

echo "==> Sample suspicious rows (screenshot):"
hdfs dfs -cat "${HDFS_AGG}/part-*" | awk -F'\t' '$6==1 {print}' | head -50
echo "Done."
