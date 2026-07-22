-- M1 — Parse Apache Combined logs from HDFS into contracted TSV.
-- Usage:
--   source config.env
--   pig -f scripts/02_pig_parse.pig \
--       -param INPUT_GLOB=/data/security/logs/*/*/*/access.log \
--       -param OUTPUT=/data/security/parsed

raw = LOAD '$INPUT_GLOB' USING TextLoader AS (line:chararray);

parsed = FOREACH raw GENERATE
  REGEX_EXTRACT(line, '^(\\S+)', 1) AS ip,
  REGEX_EXTRACT(line, '\\[(\\d{2}/\\w{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2})', 1) AS ts,
  REGEX_EXTRACT(line, '"(\\w+)\\s+', 1) AS method,
  REGEX_EXTRACT(line, '"\\w+\\s+(\\S+)\\s+HTTP/', 1) AS endpoint,
  REGEX_EXTRACT(line, '"\\s+(\\d{3})\\s+', 1) AS status,
  REGEX_EXTRACT(line, '"[^"]*"\\s+"([^"]*)"\\s*$', 1) AS ua;

clean = FILTER parsed BY
  ip IS NOT NULL AND ts IS NOT NULL AND method IS NOT NULL
  AND endpoint IS NOT NULL AND status IS NOT NULL;

with_hour = FOREACH clean {
  -- hour_bucket = yyyy-MM-dd-HH (UTC / +0000 logs)
  hb = ToString(ToDate(ts, 'dd/MMM/yyyy:HH:mm:ss'), 'yyyy-MM-dd-HH');
  GENERATE
    ip,
    ts,
    hb AS hour_bucket,
    method,
    endpoint,
    status,
    ((ua IS NULL OR ua == '') ? '-' : ua) AS user_agent;
};

rmf $OUTPUT;
STORE with_hour INTO '$OUTPUT' USING PigStorage('\t');
