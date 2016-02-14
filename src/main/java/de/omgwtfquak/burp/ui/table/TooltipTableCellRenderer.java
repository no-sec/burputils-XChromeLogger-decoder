package de.omgwtfquak.burp.ui.table;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import de.omgwtfquak.burp.XChromeLogger.SourceFile;

public class TooltipTableCellRenderer extends DefaultTableCellRenderer {

  private static final long serialVersionUID = -6301591703180986765L;

  @Override
  public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
    JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
    String pathValue = "";

    if (value instanceof SourceFile)
      pathValue = ((SourceFile) value).getFileNameContainsPath();

    c.setToolTipText(pathValue);
    setForeground(Color.BLACK);
    return c;
  }
}
