package de.omgwtfquak.burp.XChromeLogger;

public class SourceFile {

  private final String fileName;
  private final String fileNameContainsPath;

  public SourceFile(final String fileName, final String fileNameContainsPath) {
    this.fileName = fileName;
    this.fileNameContainsPath = fileNameContainsPath;
  }

  public String getFileName() {
    return fileName;
  }

  public String getFileNameContainsPath() {
    return fileNameContainsPath;
  }

  @Override
  public String toString() {
    return fileName;
  }
}
