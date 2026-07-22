# Assignment requirements checklist — Problem 13 / Group 13

Mark each item only when **done on OSHA** (or offline where noted). This is a graded assignment submission, not a walkthrough.

## Code (goes in GROUP_13_Code.zip)

- [x] HDFS ingest script with date partitions
- [x] Pig Latin parser (IP, ts, method, endpoint, status)
- [x] Java MapReduce counting 4xx and 5xx per IP per hour
- [x] Threshold flagging (default > 50)
- [x] Hive external tables + analysis views/queries
- [x] HBase table with TTL + load of top suspicious IPs
- [x] CSV + incident report generator
- [x] Sample dataset + planted threat IPs
- [ ] Built `suspicious-ip-detection-1.0.jar` (build on OSHA with Maven)
- [ ] Zip named exactly `GROUP_13_Code.zip`

## Report (becomes GROUP_13.pdf)

- [x] Draft report body with methodology and contribution table template (`report/GROUP_13_Report_DRAFT.md`)
- [ ] Contribution table: **three real names + ID numbers** (no blank / “No Contribution”)
- [ ] Screenshot: HDFS `ls -R` date partitions
- [ ] Screenshot: Pig success + sample parsed rows
- [ ] Screenshot: MapReduce job log + flagged rows
- [ ] Screenshot: Hive SHOW/DESCRIBE + analysis queries
- [ ] Screenshot: HBase `describe` (TTL) + `scan`
- [ ] Lab-regenerated CSV + incident figures pasted into PDF
- [ ] Export PDF named exactly `GROUP_13.pdf`

## Taxila upload

- [ ] One member uploads `GROUP_13.pdf` + `GROUP_13_Code.zip` before 6 Aug 2026
- [ ] Nothing submitted outside Taxila
