package de.omgwtfquak.burp.common;

import java.io.PrintWriter;

import burp.IBurpExtenderCallbacks;

/**
 * Eigene Logger Klasse, welche in die BurpConsole schreibt
 * 
 * @author mawn
 * 
 */
public class Logger {

  private static Logger log = null;
  private static PrintWriter stdout;
  private static PrintWriter stderr;

  /**
   * leerer Konstruktor, da Singleton
   */
  private Logger(IBurpExtenderCallbacks callbacks) {
    stdout = new PrintWriter(callbacks.getStdout(), true);
    stderr = new PrintWriter(callbacks.getStderr(), true);
  }

  public static synchronized Logger getInstance(IBurpExtenderCallbacks callbacks) {
    if (log == null)
      Logger.log = new Logger(callbacks);
    return log;
  }

  public static void infoLog(final String message) {
    stdout.println(message);
  }

  public static void errorLog(final String message) {
    stderr.println(message);
  }
}
