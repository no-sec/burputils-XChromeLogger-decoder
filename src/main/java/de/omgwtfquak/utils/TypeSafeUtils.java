package de.omgwtfquak.utils;

import org.json.simple.JSONArray;

public class TypeSafeUtils {

  public static String getStringInstance(final Object o) {
    if (o instanceof String) {
      return (String) o;
    } else {
      return null;
    }
  }

  public static JSONArray getJSONArrayInstance(final Object o) {
    if (o instanceof JSONArray) {
      return (JSONArray) o;
    } else {
      return null;
    }
  }

}
