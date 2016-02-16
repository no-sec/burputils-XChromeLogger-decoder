package de.omgwtfquak.burp.ui.table;

import javax.swing.table.DefaultTableModel;

/**
 * {@link DefaultTableModel} which to set specific model settings
 * 
 * @author marko
 */
public class BurpTableModel extends DefaultTableModel {

  @Override
  public boolean isCellEditable(int row, int col) {
    return false;
  }

}
