#!/usr/bin/env bash
# Create Taxila code archive: GROUP_13_Code.zip
# Run from repo root. Prefer building the JAR first on a machine with Maven/JDK8.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT="${1:-GROUP_13_Code.zip}"
STAGE="$(mktemp -d)"
NAME="GROUP_13_Code"
DEST="$STAGE/$NAME"
mkdir -p "$DEST"

if [[ ! -f mapreduce/target/suspicious-ip-detection-1.0.jar ]]; then
  echo "WARNING: JAR missing. Build on OSHA: (cd mapreduce && mvn -DskipTests package)" >&2
  echo "         Zip will still be created with sources." >&2
fi

rsync -a \
  --exclude '.git' \
  --exclude '.gitignore' \
  --exclude 'Problem_13.docx' \
  --exclude 'GROUP_13_Code.zip' \
  --exclude 'GROUP_13.pdf' \
  --exclude 'mapreduce/target/classes' \
  --exclude 'mapreduce/target/generated-*' \
  --exclude 'mapreduce/target/maven-*' \
  --exclude 'mapreduce/target/test-*' \
  --exclude 'report/hbase_puts.tmp' \
  ./ "$DEST/"

# Keep the built jar if present
if [[ -f mapreduce/target/suspicious-ip-detection-1.0.jar ]]; then
  mkdir -p "$DEST/mapreduce/target"
  cp -f mapreduce/target/suspicious-ip-detection-1.0.jar "$DEST/mapreduce/target/"
fi

rm -f "$OUT"
( cd "$STAGE" && zip -qr "$ROOT_DIR/$OUT" "$NAME" )
rm -rf "$STAGE"

echo "Wrote $ROOT_DIR/$OUT"
unzip -l "$OUT" | head -40
