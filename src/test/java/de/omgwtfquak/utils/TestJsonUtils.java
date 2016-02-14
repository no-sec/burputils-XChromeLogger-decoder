package de.omgwtfquak.utils;

import java.io.File;
import java.io.IOException;

import junit.framework.Assert;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import de.omgwtfquak.burp.XChromeLogger.XChromeLogger;

public class TestJsonUtils {

  @Test
  public void testParseXChromeLogger() {

    try {
      File dataFile = FileUtils.toFile(this.getClass().getClassLoader().getResource("test.txt"));
      String json = FileUtils.readFileToString(dataFile);
      XChromeLogger chromeLogger = JsonUtil.parseXChromeLoggerJsonFromString(json);
      Assert.assertEquals("4.1.0", chromeLogger.getVersion());
    } catch (IOException e) {
      e.printStackTrace();
      Assert.fail();
    }
  }

}
