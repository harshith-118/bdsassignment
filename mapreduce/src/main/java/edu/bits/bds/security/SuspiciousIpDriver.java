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
 *     edu.bits.bds.security.SuspiciousIpDriver \
 *     <parsed_input> <agg_output> [threshold]
 */
public class SuspiciousIpDriver extends Configured implements Tool {

  @Override
  public int run(String[] args) throws Exception {
    if (args.length < 2) {
      System.err.println("Usage: SuspiciousIpDriver <parsed_input> <agg_output> [threshold]");
      return 1;
    }
    String input = args[0];
    String output = args[1];
    int threshold = 50;
    if (args.length >= 3) {
      threshold = Integer.parseInt(args[2]);
    }

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

  public static void main(String[] args) throws Exception {
    int code = ToolRunner.run(new Configuration(), new SuspiciousIpDriver(), args);
    System.exit(code);
  }
}
