package de.omgwtfquak.burp.common;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

/**
 * Hilfsklasse mit haeufig benoetigten Methoden
 * 
 * @author mawn
 * 
 */
public class Helper {

  private final IBurpExtenderCallbacks callbacks;
  private final IExtensionHelpers helpers;
  private static Helper help = null;

  /**
   * leerer Konstruktor, da Singleton
   */
  private Helper(final IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    this.helpers = callbacks.getHelpers();
  }

  /**
   * Bekomme die Instanz des {@link Helper}s und kann nach dem Erstaufruf mit NULL geholt werden
   * 
   * @param callbacks
   *          {@link IBurpExtenderCallbacks} der Burp API fuer die {@link IExtensionHelpers} und {@link IBurpExtenderCallbacks} Helferklassen
   * @return {@link Helper} Instanz
   */
  public static synchronized Helper getInstance(IBurpExtenderCallbacks callbacks) {
    if (help == null)
      Helper.help = new Helper(callbacks);
    return help;
  }

  /**
   * Durchsucht das uebergebene {@link Byte} Array nach einem {@link Byte} Match und gibt ein {@link Integer} Array zurueck, welches den Start- und
   * Endindex des Match beinhaltet.
   * 
   * @param traffic
   *          {@link Byte}[], welches den kompletten Traffic beinhaltet (Request bzw. Response)
   * @param match
   *          {@link Byte}[], die den GREP String beinhaltet
   * @return {@link List}<{@link Integer}[]> Gibt eine Liste mit Integer Arrays zurueck, falls der GREP String mehrfach vorhanden ist
   */
  public List<int[]> getMatches(final byte[] traffic, final byte[] match) {
    List<int[]> matches = new ArrayList<int[]>();

    int start = 0;
    while (start < traffic.length) {
      start = helpers.indexOf(traffic, match, false, start, traffic.length);
      if (start == -1)
        break;
      matches.add(new int[] { start, start + match.length });
      start += match.length;
    }
    return matches;
  }

  /**
   * Durchsucht das uebergebene {@link Byte} Array anhand eines regulaeren Ausrucks und gibt ein {@link Integer} Array zurueck, welches den Start- und
   * Endindex des Match beinhaltet.
   * 
   * @param traffic
   *          {@link Byte}[], welches den kompletten Traffic beinhaltet (Request bzw. Response)
   * @param regex
   *          {@link String} der regulaere Ausdruck anhand der Traffic durchsucht wird
   * @return {@link List}<{@link Integer}[]> Gibt eine Liste mit Integer Arrays zurueck, falls der RegEx String mehrfach vorhanden ist
   * @throws UnsupportedEncodingException
   */
  public List<int[]> getMatches(final byte[] traffic, final String regex) throws UnsupportedEncodingException {
    List<int[]> matches = new ArrayList<int[]>();
    String trafficAsString = StringUtils.toString(traffic, "UTF-8");
    Pattern p = Pattern.compile(regex);
    Matcher m = p.matcher(trafficAsString);
    // TODO mehrfach finding?
    if (m.find()) {
      matches.add(new int[] { m.start(), m.end() });
    }
    return matches;
  }

  /**
   * Fuegt ein Request {@link CustomScanIssue} zum Scanner hinzu
   * 
   * @param issues
   *          {@link List}<{@link IScanIssue}> enthaelt die Liste der aktuellen {@link IScanIssue}s und fuegt einen neuen hinzu
   * @param baseRequestResponse
   *          {@link IHttpRequestResponse} enthaelt den Request/Response
   * @param matches
   *          {@link List}<{@link Integer}> enthaelt die Indexes fuer das Highlighting in der Scanner GUI
   * @param issueName
   *          {@link String} Name des Issues
   * @param issueDetail
   *          {@link String} Beschreibung des Issues
   * @param severity
   *          {@link String} Schwere des Issues
   * @param confidence
   *          {@link String} Wahrscheinlichkeit des Issues
   */
  public void addRequestIssue(List<IScanIssue> issues, final IHttpRequestResponse baseRequestResponse, final List<int[]> matches,
      final String issueName, final String issueDetail, final String severity, final String confidence) {
    issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), helpers.analyzeRequest(baseRequestResponse).getUrl(),
        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, matches, null) }, issueName, issueDetail, severity, confidence));
  }

  /**
   * Fuegt ein Response {@link CustomScanIssue} zum Scanner hinzu
   * 
   * @param issues
   *          {@link List}<{@link IScanIssue}> enthaelt die Liste der aktuellen {@link IScanIssue}s und fuegt einen neuen hinzu
   * @param baseRequestResponse
   *          {@link IHttpRequestResponse} enthaelt den Request/Response
   * @param matches
   *          {@link List}<{@link Integer}> enthaelt die Indexes fuer das Highlighting in der Scanner GUI
   * @param issueName
   *          {@link String} Name des Issues
   * @param issueDetail
   *          {@link String} Beschreibung des Issues
   * @param severity
   *          {@link String} Schwere des Issues
   * @param confidence
   *          {@link String} Wahrscheinlichkeit des Issues
   */
  public void addResponseIssue(List<IScanIssue> issues, final IHttpRequestResponse baseRequestResponse, final List<int[]> matches,
      final String issueName, final String issueDetail, final String severity, final String confidence) {
    issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), helpers.analyzeRequest(baseRequestResponse).getUrl(),
        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, issueName, issueDetail, severity, confidence));
  }
}
