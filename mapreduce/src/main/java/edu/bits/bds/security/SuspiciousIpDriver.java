package edu.bits.bds.security;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

/**
 * Driver: aggregate 4xx/5xx per IP per hour; flag when error_count > threshold.
 *
 * Usage:
 *   hadoop jar suspicious-ip-detection-1.0.jar \
 *     <parsed_input> <agg_output> [threshold]
 *
 *   # or explicitly:
 *   hadoop jar suspicious-ip-detection-1.0.jar \
 *     edu.bits.bds.security.SuspiciousIpDriver \
 *     <parsed_input> <agg_output> [threshold]
 */
public class SuspiciousIpDriver extends Configured implements Tool {

  @Override
  public int run(String[] args) throws Exception {
    // Some Hadoop invocations pass the main class name as args[0].
    args = normalizeArgs(args);

    if (args.length < 2) {
      System.err.println("Usage: SuspiciousIpDriver <parsed_input> <agg_output> [threshold]");
      return 1;
    }
    String input = args[0];
    String output = args[1];
    int threshold = 50;
    if (args.length >= 3) {
      try {
        threshold = Integer.parseInt(args[2]);
      } catch (NumberFormatException e) {
        System.err.println("Invalid threshold '" + args[2] + "'; expected an integer. Using 50.");
        threshold = 50;
      }
    }

    System.out.println("MR input=" + input + " output=" + output + " threshold=" + threshold);

    Configuration conf = getConf();
    conf.setInt(ErrorCountReducer.CONF_THRESHOLD, threshold);

    Job job = Job.getInstance(conf, "suspicious-ip-error-count");
    job.setJarByClass(SuspiciousIpDriver.class);

    job.setMapperClass(ErrorCountMapper.class);
    job.setReducerClass(ErrorCountReducer.class);

    job.setMapOutputKeyClass(Text.class);
    job.setMapOutputValueClass(Text.class);
    job.setOutputKeyClass(Text.class);
    job.setOutputValueClass(Text.class);

    job.setInputFormatClass(TextInputFormat.class);
    job.setOutputFormatClass(TextOutputFormat.class);

    FileInputFormat.addInputPath(job, new Path(input));
    FileOutputFormat.setOutputPath(job, new Path(output));

    boolean ok = job.waitForCompletion(true);
    return ok ? 0 : 1;
  }

  /** Drop leading main-class token if present so paths/threshold line up. */
  static String[] normalizeArgs(String[] args) {
    if (args.length >= 3 && args[0] != null
        && args[0].contains("SuspiciousIpDriver")
        && args[1].startsWith("/")
        && args[2].startsWith("/")) {
      String[] fixed = new String[args.length - 1];
      System.arraycopy(args, 1, fixed, 0, fixed.length);
      return fixed;
    }
    return args;
  }

  public static void main(String[] args) throws Exception {
    int code = ToolRunner.run(new Configuration(), new SuspiciousIpDriver(), args);
    System.exit(code);
  }
}
