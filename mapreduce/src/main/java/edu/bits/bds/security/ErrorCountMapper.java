package edu.bits.bds.security;

import java.io.IOException;

import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Mapper;

/**
 * Reads Pig-parsed TSV:
 * ip, ts, hour_bucket, method, endpoint, status, user_agent
 * Emits key=ip\\thour_bucket, value=4xx|5xx for error statuses only.
 */
public class ErrorCountMapper extends Mapper<LongWritable, Text, Text, Text> {

  private final Text outKey = new Text();
  private final Text outVal = new Text();

  @Override
  protected void map(LongWritable key, Text value, Context context)
      throws IOException, InterruptedException {
    String line = value.toString().trim();
    if (line.isEmpty()) {
      return;
    }
    String[] parts = line.split("\t", -1);
    if (parts.length < 6) {
      context.getCounter("DATA", "MALFORMED_ROWS").increment(1);
      return;
    }
    String ip = parts[0].trim();
    String hourBucket = parts[2].trim();
    String statusStr = parts[5].trim();
    if (ip.isEmpty() || hourBucket.isEmpty() || statusStr.isEmpty()) {
      context.getCounter("DATA", "MALFORMED_ROWS").increment(1);
      return;
    }
    int status;
    try {
      status = Integer.parseInt(statusStr);
    } catch (NumberFormatException e) {
      context.getCounter("DATA", "BAD_STATUS").increment(1);
      return;
    }
    if (status < 400 || status > 599) {
      context.getCounter("DATA", "NON_ERROR_SKIPPED").increment(1);
      return;
    }
    outKey.set(ip + "\t" + hourBucket);
    if (status <= 499) {
      outVal.set("4xx");
      context.getCounter("DATA", "MAPPED_4XX").increment(1);
    } else {
      outVal.set("5xx");
      context.getCounter("DATA", "MAPPED_5XX").increment(1);
    }
    context.write(outKey, outVal);
  }
}
