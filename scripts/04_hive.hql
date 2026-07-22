-- M3 — Hive DDL, views, and top-10 export for security analytics.
-- Compatible with Hive 1.2+/2.x/3.x (no window functions required).
-- Usage:
--   source config.env
--   hive -f scripts/04_hive.hql

CREATE DATABASE IF NOT EXISTS security_analytics;
USE security_analytics;

DROP TABLE IF EXISTS ext_parsed_logs;
CREATE EXTERNAL TABLE ext_parsed_logs (
  ip            STRING,
  ts            STRING,
  hour_bucket   STRING,
  method        STRING,
  endpoint      STRING,
  status        STRING,
  user_agent    STRING
)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY '\t'
STORED AS TEXTFILE
LOCATION '/data/security/parsed';

DROP TABLE IF EXISTS ext_ip_hour_agg;
CREATE EXTERNAL TABLE ext_ip_hour_agg (
  ip              STRING,
  hour_bucket     STRING,
  count_4xx       BIGINT,
  count_5xx       BIGINT,
  error_count     BIGINT,
  is_suspicious   INT,
  reason          STRING
)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY '\t'
STORED AS TEXTFILE
LOCATION '/data/security/agg/ip_hour';

DROP VIEW IF EXISTS v_flagged_ips;
CREATE VIEW v_flagged_ips AS
SELECT *
FROM ext_ip_hour_agg
WHERE is_suspicious = 1;

DROP VIEW IF EXISTS v_flagged_week_summary;
CREATE VIEW v_flagged_week_summary AS
SELECT
  ip,
  SUM(error_count) AS total_violations,
  MAX(error_count) AS peak_errors,
  COUNT(DISTINCT hour_bucket) AS suspicious_hours,
  MAX(reason) AS reason
FROM v_flagged_ips
GROUP BY ip;

DROP VIEW IF EXISTS v_flagged_endpoints;
CREATE VIEW v_flagged_endpoints AS
SELECT
  f.ip,
  COUNT(DISTINCT p.endpoint) AS endpoint_diversity
FROM v_flagged_ips f
JOIN ext_parsed_logs p
  ON f.ip = p.ip
WHERE CAST(p.status AS INT) BETWEEN 400 AND 599
GROUP BY f.ip;

-- Screenshot queries
SHOW TABLES;
DESCRIBE ext_ip_hour_agg;

SELECT * FROM v_flagged_week_summary ORDER BY total_violations DESC;

SELECT ip, endpoint_diversity
FROM v_flagged_endpoints
ORDER BY endpoint_diversity DESC;

-- Peak hour per IP via join on max error_count (no window fn)
DROP TABLE IF EXISTS tmp_top10;
CREATE TABLE tmp_top10 AS
SELECT
  w.ip,
  p.hour_bucket AS peak_hour,
  w.peak_errors,
  w.total_violations,
  COALESCE(e.endpoint_diversity, CAST(0 AS BIGINT)) AS endpoint_diversity,
  CASE
    WHEN w.peak_errors >= 100 OR w.total_violations >= 200 THEN 'High'
    ELSE 'Medium'
  END AS threat_level,
  w.reason
FROM v_flagged_week_summary w
LEFT JOIN v_flagged_ips p
  ON w.ip = p.ip AND w.peak_errors = p.error_count
LEFT JOIN v_flagged_endpoints e
  ON w.ip = e.ip
ORDER BY w.total_violations DESC
LIMIT 10;

SELECT * FROM tmp_top10;

INSERT OVERWRITE DIRECTORY '/data/security/export/top10_suspicious'
ROW FORMAT DELIMITED FIELDS TERMINATED BY '\t'
SELECT
  ip,
  peak_hour,
  peak_errors,
  total_violations,
  endpoint_diversity,
  threat_level,
  reason
FROM tmp_top10;
