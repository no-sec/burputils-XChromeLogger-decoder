package de.omgwtfquak.burp.XChromeLogger;

import java.util.ArrayList;

/**
 * Represents a complete base64 decoded XChromeLogger instance
 * 
 * @author marko
 */
public class XChromeLogger {

  private final String version;
  private final String type;
  private final String requestUri;
  private final ArrayList<XChromeLoggerStruct> xChromeLoggerStructAsList;

  public XChromeLogger(final String version, final String type, final String requestUri) {
    this.version = version;
    this.type = type;
    this.requestUri = requestUri;
    this.xChromeLoggerStructAsList = new ArrayList<XChromeLoggerStruct>();
  }

  /**
   * get version of the XChromeLogger data
   * 
   * @return
   */
  public String getVersion() {
    return version;
  }

  /**
   * get the type of the XChromeLogger data
   * 
   * @return
   */
  public String getType() {
    return type;
  }

  /**
   * get the URI of the requested resource
   * 
   * @return
   */
  public String getRequestUri() {
    return requestUri;
  }

  /**
   * get all {@link XChromeLoggerStruct}
   * 
   * @return
   */
  public ArrayList<XChromeLoggerStruct> getxChromeLoggerStructAsList() {
    return xChromeLoggerStructAsList;
  }

  /**
   * add a new {@link XChromeLoggerStruct} to the list
   * 
   * @param xChromeLoggerStruct
   */
  public void addXChromeLoggerStruct(final XChromeLoggerStruct xChromeLoggerStruct) {
    this.xChromeLoggerStructAsList.add(xChromeLoggerStruct);
  }
}
