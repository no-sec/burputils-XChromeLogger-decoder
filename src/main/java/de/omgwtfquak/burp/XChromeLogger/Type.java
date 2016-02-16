package de.omgwtfquak.burp.XChromeLogger;

/**
 * Different types of XChromeLogger data
 * 
 * @author marko
 */
public enum Type {
  LOG("log"), WARN("warn"), ERROR("error"), INFO("info");

  private String s;

  Type(final String s) {
    this.s = s;
  }

  public String getType() {
    return this.s;
  }

  public static Type fromString(final String type) {
    if (type != null)
      for (Type t : Type.values())
        if (type.equalsIgnoreCase(t.s))
          return t;

    return LOG;
  }
}