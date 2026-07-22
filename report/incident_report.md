# Incident Report — Server Log Security Threat Detection

**Group:** 13  
**Generated:** 2026-07-22 16:57 UTC  
**Detection rule:** IP with more than 50 HTTP 4xx+5xx responses in any single hour is flagged (`HIGH_ERROR_RATE`).

## Summary

This report lists the **top 4** suspicious source IPs identified from Apache Combined access logs via the Hadoop pipeline (HDFS → Pig → MapReduce → Hive → HBase).

## Top suspicious IPs

| IP | Peak hour | Peak errors | Total violations | Endpoints | Threat | Reason |
|----|-----------|-------------|------------------|-----------|--------|--------|
| 198.51.100.66 | 2026-07-17-10 | 80 | 80 | 80 | Medium | HIGH_ERROR_RATE |
| 203.0.113.10 | 2026-07-17-14 | 70 | 70 | 2 | Medium | HIGH_ERROR_RATE |
| 198.51.100.20 | 2026-07-17-15 | 60 | 115 | 40 | High | HIGH_ERROR_RATE |
| 203.0.113.77 | 2026-07-17-18 | 55 | 55 | 3 | Medium | HIGH_ERROR_RATE |

## Recommended actions

1. **High** threat IPs — block or rate-limit at the edge; confirm in HBase blacklist.
2. **Medium** threat IPs — elevate monitoring; retain in blacklist until TTL expiry (7 days).
3. Review `/login`, `/admin`, and scan-like paths for hardening (WAF rules, fail2ban, MFA).
4. Re-run the pipeline daily; HBase CF TTL auto-expires stale blacklist rows.

## Pipeline evidence

- HDFS date-partitioned raw logs under `/data/security/logs/`
- Pig-parsed fields under `/data/security/parsed/`
- MapReduce IP-hour aggregates under `/data/security/agg/ip_hour/`
- Hive views `v_flagged_week_summary`, `v_flagged_endpoints`
- HBase table `security_ip_blacklist` (CF `info`, TTL 604800s)
