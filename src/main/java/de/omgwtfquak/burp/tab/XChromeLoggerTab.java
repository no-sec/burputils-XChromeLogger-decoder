package de.omgwtfquak.burp.tab;

import java.awt.Component;

import org.apache.commons.lang3.StringUtils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import de.omgwtfquak.burp.XChromeLogger.XChromeLogger;
import de.omgwtfquak.burp.XChromeLogger.XChromeLoggerComponent;
import de.omgwtfquak.burp.common.Logger;
import de.omgwtfquak.utils.JsonUtil;

public class XChromeLoggerTab implements IMessageEditorTab {

  private final boolean editable;
  private final IExtensionHelpers helpers;
  private final XChromeLoggerComponent component;
  private final Logger LOG;
  private final IBurpExtenderCallbacks callbacks;

  /**
   * Standard Konstrukter, welcher den {@link IMessageEditorController} und {@link IBurpExtenderCallbacks} uebergibt, um die enstprechenden Interfaces
   * nachzuholen
   * 
   * @param controller
   * @param callbacks
   * @param editable
   */
  public XChromeLoggerTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks, boolean editable) {

    this.editable = editable;
    // FIXME Debug
    Object[] columns = { "Logger Data", "Class", "Line" };
    XChromeLoggerComponent component = new XChromeLoggerComponent(columns);
    this.component = component;
    this.callbacks = callbacks;
    this.LOG = Logger.getInstance(callbacks);
    this.helpers = callbacks.getHelpers();
  }

  @Override
  public String getTabCaption() {
    return "Server Log";
  }

  @Override
  public Component getUiComponent() {
    return component;
  }

  @Override
  public boolean isEnabled(byte[] content, boolean isRequest) {
    return !isRequest && containsXChromeLoggerData(content);
  }

  @Override
  public void setMessage(byte[] content, boolean isRequest) {

    if (!isRequest || containsXChromeLoggerData(content)) {
      byte[] decodedLoggerData = extractXChromeLoggerData(content);
      XChromeLogger xChromeLogger = JsonUtil.parseXChromeLoggerJsonFromString(new String(decodedLoggerData));
      component.setTableXChromeLoggerData(xChromeLogger);
    }
  }

  @Override
  public byte[] getMessage() {
    return null;
  }

  @Override
  public boolean isModified() {
    return false;
  }

  @Override
  public byte[] getSelectedData() {
    return null;
  }

  /**
   * Check if the HTTP Response Header contains XChromeLoggerData
   * 
   * @param content
   *          Http Response as Byte Stream
   * @return <code>true</code> if Http Response contains XChromeLoggerData
   */
  private boolean containsXChromeLoggerData(final byte[] content) {
    for (String header : helpers.analyzeResponse(content).getHeaders())
      if (StringUtils.contains(header, "X-ChromeLogger-Data:")) {
        return true;
      }
    return false;
  }

  private byte[] extractXChromeLoggerData(final byte[] content) {
    for (String header : helpers.analyzeResponse(content).getHeaders())
      if (StringUtils.contains(header, "X-ChromeLogger-Data:")) {
        String encodedLoggerData = StringUtils.substringAfter(header, ":");
        return helpers.base64Decode(encodedLoggerData);
      }
    return "".getBytes();
  }

}
