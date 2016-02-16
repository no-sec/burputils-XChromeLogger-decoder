package de.omgwtfquak.burp.common;

import java.io.PrintWriter;

import burp.IBurpExtenderCallbacks;

/**
 * Log class to write log data in burp ui output
 * 
 * @author marko
 * 
 */
public class Logger {

  private static Logger log = null;
  private static PrintWriter stdout;
  private static PrintWriter stderr;

  /**
   * empty constructor
   */
  private Logger(IBurpExtenderCallbacks callbacks) {
    stdout = new PrintWriter(callbacks.getStdout(), true);
    stderr = new PrintWriter(callbacks.getStderr(), true);
  }

  /**
   * get logger instance to write logger output
   * 
   * @param callbacks
   * @return
   */
  public static synchronized Logger getInstance(IBurpExtenderCallbacks callbacks) {
    if (log == null)
      Logger.log = new Logger(callbacks);
    return log;
  }

  /**
   * write to burp info log
   * 
   * @param message
   */
  public static void infoLog(final String message) {
    stdout.println(message);
  }

  /**
   * write to burp error log
   * 
   * @param message
   */
  public static void errorLog(final String message) {
    stderr.println(message);
  }
}
