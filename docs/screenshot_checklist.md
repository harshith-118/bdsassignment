# Screenshot checklist — Group 13

Capture these on **OSHA Linux** for `GROUP_13.pdf`:

1. **HDFS** — `hdfs dfs -ls -R /data/security/logs` (date partitions visible)
2. **Pig** — job success output + sample parsed rows (`hdfs dfs -cat ... | head`)
3. **MapReduce** — YARN/MR job log (or console counters) + suspicious rows (`is_suspicious=1`)
4. **Hive** — `SHOW TABLES;` / `DESCRIBE ext_ip_hour_agg;`
5. **Hive** — `SELECT * FROM v_flagged_week_summary ...`
6. **Hive** — endpoint diversity and/or top-10 query result
7. **HBase** — `describe 'security_ip_blacklist'` (TTL visible on CF `info`)
8. **HBase** — `scan 'security_ip_blacklist'` (top IPs present)
9. **Deliverable** — CSV / incident report excerpt in the PDF
10. **Contribution table** — M1 / M2 / M3 filled with real names & IDs

## Contribution table (fill names)

| Sl. | Name | ID | Contribution |
|-----|------|-----|--------------|
| 1 | (Member A) | | **M1:** Dataset generation, HDFS date-partition ingest, Pig Combined-log parser & parsed TSV contract |
| 2 | (Member B) | | **M2:** Java MapReduce Mapper/Reducer/Driver, threshold flagging, JAR build & run scripts |
| 3 | (Member C) | | **M3:** Hive external tables/views/top-10, HBase blacklist+TTL load, CSV & incident report, PDF screenshots |
