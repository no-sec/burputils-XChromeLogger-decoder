package de.omgwtfquak.burp.ui.table;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * CellRenderer which sets the color of cell text to black
 * 
 * @author marko
 */
public class BurpCellRenderer extends DefaultTableCellRenderer {

  private static final long serialVersionUID = -3679941533751250170L;

  @Override
  public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
    JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
    setForeground(Color.BLACK);
    return c;
  }

}
