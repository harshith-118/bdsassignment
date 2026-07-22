package edu.bits.bds.security;

import java.io.IOException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Reducer;

/**
 * Aggregates 4xx/5xx counts per IP-hour and flags suspicious IPs.
 * Output TSV:
 * ip, hour_bucket, count_4xx, count_5xx, error_count, is_suspicious, reason
 */
public class ErrorCountReducer extends Reducer<Text, Text, Text, Text> {

  public static final String CONF_THRESHOLD = "security.error.threshold";
  private static final String REASON = "HIGH_ERROR_RATE";

  private int threshold = 50;
  private final Text outKey = new Text();
  private final Text outVal = new Text();

  @Override
  protected void setup(Context context) {
    Configuration conf = context.getConfiguration();
    threshold = conf.getInt(CONF_THRESHOLD, 50);
  }

  @Override
  protected void reduce(Text key, Iterable<Text> values, Context context)
      throws IOException, InterruptedException {
    long count4 = 0;
    long count5 = 0;
    for (Text v : values) {
      String tag = v.toString();
      if ("4xx".equals(tag)) {
        count4++;
      } else if ("5xx".equals(tag)) {
        count5++;
      }
    }
    long total = count4 + count5;
    int suspicious = total > threshold ? 1 : 0;
    String reason = suspicious == 1 ? REASON : "-";

    // key is already "ip\thour"
    outKey.set(key.toString());
    outVal.set(count4 + "\t" + count5 + "\t" + total + "\t" + suspicious + "\t" + reason);
    context.write(outKey, outVal);

    if (suspicious == 1) {
      context.getCounter("THREAT", "SUSPICIOUS_IP_HOURS").increment(1);
    }
  }
}
