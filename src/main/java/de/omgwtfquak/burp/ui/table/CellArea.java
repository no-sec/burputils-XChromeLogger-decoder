package de.omgwtfquak.burp.ui.table;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.font.FontRenderContext;
import java.awt.font.LineBreakMeasurer;
import java.awt.font.TextAttribute;
import java.awt.font.TextLayout;
import java.text.AttributedCharacterIterator;
import java.text.AttributedString;
import java.text.BreakIterator;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import de.omgwtfquak.burp.XChromeLogger.Type;
import de.omgwtfquak.burp.XChromeLogger.XChromeLogger;
import de.omgwtfquak.burp.XChromeLogger.XChromeLoggerStruct;

/**
 * Cell from {@link DefaultTableCellRenderer} which perform auto sizing of the text of a {@link MultilineCellRenderer}
 * 
 * @author marko
 */
public class CellArea extends DefaultTableCellRenderer {

  private static final long serialVersionUID = 4370852586252846822L;
  private final String text;
  protected int row;
  protected int column;
  protected JTable table;
  protected Font font;
  private int paragraphStart, paragraphEnd;
  private LineBreakMeasurer lineMeasurer;

  /**
   * constructor
   * 
   * @param o
   * @param table
   * @param row
   * @param column
   * @param isSelected
   */
  public CellArea(final Object o, final JTable table, final int row, final int column, final boolean isSelected) {

    this.text = o.toString();
    this.row = row;
    this.column = column;
    this.table = table;

    if (o instanceof XChromeLoggerStruct)
      setForeground(getFontColorFromType(((XChromeLoggerStruct) o).getType()));
    else
      setForeground(Color.BLACK);

    if (isSelected) {
      setBackground(this.table.getSelectionBackground());
    }
  }

  @Override
  public void paintComponent(final Graphics gr) {
    super.paintComponent(gr);
    if (text != null && !text.isEmpty()) {
      Graphics2D g = (Graphics2D) gr;
      if (lineMeasurer == null) {
        AttributedString cellContent = new AttributedString(this.text);
        cellContent.addAttribute(TextAttribute.FONT, this.font);
        AttributedCharacterIterator paragraph = cellContent.getIterator();
        paragraphStart = paragraph.getBeginIndex();
        paragraphEnd = paragraph.getEndIndex();
        FontRenderContext frc = g.getFontRenderContext();
        lineMeasurer = new LineBreakMeasurer(paragraph, BreakIterator.getWordInstance(), frc);
      }
      float breakWidth = table.getColumnModel().getColumn(column).getWidth();
      float drawPosY = 0;
      lineMeasurer.setPosition(paragraphStart);
      while (lineMeasurer.getPosition() < paragraphEnd) {
        TextLayout layout = lineMeasurer.nextLayout(breakWidth);
        float drawPosX = layout.isLeftToRight() ? 0 : breakWidth - layout.getAdvance();
        drawPosY += layout.getAscent();
        layout.draw(g, drawPosX, drawPosY);
        drawPosY += layout.getDescent() + layout.getLeading();
      }
      table.setRowHeight(row, (int) drawPosY);
    }
  }

  /**
   * get font color depeding on XChromeLogger {@link Type}
   * 
   * @param type
   *          of {@link XChromeLogger}
   * @return font color
   */
  private Color getFontColorFromType(final Type type) {

    int color = 0x330000;

    switch (type) {
      case LOG:
        break;
      case WARN:
        color = 0xFF8000;
      case INFO:
        color = 0x3333FF;
      case ERROR:
        color = 0xFF0000;
      default:
        break;
    }

    return new Color(color);
  }
}
