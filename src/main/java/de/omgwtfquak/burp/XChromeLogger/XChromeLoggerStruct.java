package de.omgwtfquak.burp.XChromeLogger;

import java.nio.file.Paths;

import org.apache.commons.lang3.StringUtils;

public class XChromeLoggerStruct {

  private final String data;
  private final String sourceFile;
  private final double line;
  private final String sourceFileWithPath;
  private final SourceFile file;
  private final Type type;

  public XChromeLoggerStruct(final String data, final String sourceFile, final double line, final String type) {
    this.data = data;
    this.sourceFileWithPath = StringUtils.substringBefore(sourceFile, " : ");
    this.sourceFile = Paths.get(sourceFileWithPath).getFileName().toString();
    this.file = new SourceFile(this.sourceFile, this.sourceFileWithPath);
    this.line = line;
    this.type = Type.fromString(type);
  }

  public String getData() {
    return data;
  }

  public String getSourceFile() {
    return sourceFile;
  }

  public double getLine() {
    return line;
  }

  public String getSourceFileWithPath() {
    return sourceFileWithPath;
  }

  public SourceFile getFile() {
    return file;
  }

  public Type getType() {
    return type;
  }

  /**
   * Bekomme XChromeLoggerStruct als {@link Object} mit der Reihenfolge:<br>
   * <ol>
   * <li>data</li>
   * <li>sourceFile</li>
   * <li>line</li>
   * </ol>
   * 
   * @return
   */
  public Object[] getStructAsObject() {

    String lineAsString = StringUtils.stripEnd(String.valueOf(line), ".0");

    Object[] o = { this, file, lineAsString };
    return o;
  }

  @Override
  public String toString() {
    return data;
  }
}
