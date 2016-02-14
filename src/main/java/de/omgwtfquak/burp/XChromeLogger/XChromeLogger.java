package de.omgwtfquak.burp.XChromeLogger;

import java.util.ArrayList;

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

  public String getVersion() {
    return version;
  }

  public String getType() {
    return type;
  }

  public String getRequestUri() {
    return requestUri;
  }

  public ArrayList<XChromeLoggerStruct> getxChromeLoggerStructAsList() {
    return xChromeLoggerStructAsList;
  }

  public void addXChromeLoggerStruct(final XChromeLoggerStruct xChromeLoggerStruct) {
    this.xChromeLoggerStructAsList.add(xChromeLoggerStruct);
  }
}
