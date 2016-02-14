package de.omgwtfquak.burp.XChromeLogger;

import java.awt.BorderLayout;
import java.util.ArrayList;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import de.omgwtfquak.burp.ui.table.BurpCellRenderer;
import de.omgwtfquak.burp.ui.table.BurpTable;
import de.omgwtfquak.burp.ui.table.BurpTableModel;
import de.omgwtfquak.burp.ui.table.MultilineCellRenderer;
import de.omgwtfquak.burp.ui.table.TooltipTableCellRenderer;

public class XChromeLoggerComponent extends JPanel {

  private final JScrollPane jScrollPane;
  private final JTable table;
  private final DefaultTableModel model;
  private static final long serialVersionUID = 4671429789840120389L;

  public XChromeLoggerComponent(final Object[] columns) {

    this.model = new BurpTableModel();
    this.model.setColumnIdentifiers(columns);

    this.table = new BurpTable(model);
    this.table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
    this.table.setFillsViewportHeight(true);
    this.table.getColumnModel().getColumn(0).setCellRenderer(new MultilineCellRenderer());
    this.table.getColumnModel().getColumn(1).setCellRenderer(new TooltipTableCellRenderer());
    this.table.getColumnModel().getColumn(2).setCellRenderer(new BurpCellRenderer());

    this.jScrollPane = new JScrollPane(table);
    this.setLayout(new BorderLayout());
    this.add(jScrollPane, BorderLayout.CENTER);
  }

  public void setTableXChromeLoggerData(final XChromeLogger data) {

    // first, remove all rows
    this.model.setNumRows(0);
    ArrayList<XChromeLoggerStruct> xChromeLoggerData = data.getxChromeLoggerStructAsList();

    for (XChromeLoggerStruct struct : xChromeLoggerData) {
      this.model.addRow(struct.getStructAsObject());
    }
    this.model.fireTableDataChanged();
  }
}
