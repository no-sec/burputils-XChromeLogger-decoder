package burp;

import de.omgwtfquak.burp.common.Logger;
import de.omgwtfquak.burp.tab.XChromeLoggerTab;

/**
 * This BurpSuite extension adds a new tab in the HTTP message editor to display X-ChromeLogger-Data (see https://craig.is/writing/chrome-logger) in
 * decoded form.
 * 
 * @author marko
 */
public class BurpExtender implements IBurpExtender, IExtensionStateListener, IMessageEditorTabFactory {

  private final String extensionName = "XChromelogger-Tab";
  private IBurpExtenderCallbacks callbacks;

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    // keep a reference to our callbacks object
    this.callbacks = callbacks;
    // obtain an extension helpers object
    Logger.getInstance(callbacks);

    // set our extension name
    callbacks.setExtensionName(extensionName);

    // Indicate that this class contains the method to instantiate a new Message Editor Tab
    callbacks.registerMessageEditorTabFactory(this);
  }

  @Override
  public void extensionUnloaded() {
    Logger.infoLog(extensionName + " was unloaded.");
  }

  @Override
  public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {

    // enable XChromeLogger
    return new XChromeLoggerTab(controller, callbacks, false);
  }
}
