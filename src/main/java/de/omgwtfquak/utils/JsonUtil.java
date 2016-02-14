package de.omgwtfquak.utils;

import java.util.Iterator;

import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import de.omgwtfquak.burp.XChromeLogger.XChromeLogger;
import de.omgwtfquak.burp.XChromeLogger.XChromeLoggerStruct;

public class JsonUtil {

  public static XChromeLogger parseXChromeLoggerJsonFromString(final String content) {

    JSONParser parser = new JSONParser();

    try {
      JSONObject jsonObject = (JSONObject) parser.parse(content);
      String version = TypeSafeUtils.getStringInstance(jsonObject.get("version"));
      String requestUri = TypeSafeUtils.getStringInstance(jsonObject.get("request_uri"));
      JSONArray data = TypeSafeUtils.getJSONArrayInstance(jsonObject.get("rows"));

      XChromeLogger chromeLogger = new XChromeLogger(version, "log", requestUri);
      XChromeLoggerStruct chromeLoggerStruct;
      Iterator<JSONArray> iterator = data.iterator();
      String sourceFile;
      String loggerOutput;
      String logType;
      while (iterator.hasNext()) {
        JSONArray loggerElement = TypeSafeUtils.getJSONArrayInstance(iterator.next());
        if (loggerElement != null) {
          // TODO check columns":["log","backtrace","type"] for entries
          JSONArray loggerOutputJSON = TypeSafeUtils.getJSONArrayInstance(loggerElement.get(0));
          loggerOutput = TypeSafeUtils.getStringInstance(loggerOutputJSON.get(0));
          sourceFile = TypeSafeUtils.getStringInstance(loggerElement.get(1));
          logType = TypeSafeUtils.getStringInstance(loggerElement.get(2));
          sourceFile = (sourceFile == null) ? "unknown" : sourceFile;
          double line = 0.0;
          if (!sourceFile.equals("unknown"))
            line = Double.parseDouble(StringUtils.substringAfter(sourceFile, ": "));

          chromeLoggerStruct = new XChromeLoggerStruct(loggerOutput, sourceFile, line, logType);
          chromeLogger.addXChromeLoggerStruct(chromeLoggerStruct);
        }
      }
      return chromeLogger;
    } catch (ParseException e) {
      e.printStackTrace();
    } catch (NumberFormatException e) {
      e.printStackTrace();
    }
    return null;
  }
}
