package de.omgwtfquak.burp.ui.table;

import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;

/**
 * Multline Cell
 * 
 * @author marko
 */
public class MultilineCellRenderer implements TableCellRenderer {

  @Override
  public Component getTableCellRendererComponent(final JTable table, final Object value, final boolean isSelected, final boolean hasFocus,
      final int row, int column) {
    CellArea area = new CellArea(value, table, row, column, isSelected);

    return area;
  }
}
