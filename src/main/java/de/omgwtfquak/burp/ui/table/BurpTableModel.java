package de.omgwtfquak.burp.ui.table;

import javax.swing.table.DefaultTableModel;

public class BurpTableModel extends DefaultTableModel {

  @Override
  public boolean isCellEditable(int row, int col) {
    return false;
  }

}
