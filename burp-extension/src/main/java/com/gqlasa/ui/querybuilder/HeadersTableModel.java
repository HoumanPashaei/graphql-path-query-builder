package com.gqlasa.ui.querybuilder;

import com.gqlasa.model.HeaderKV;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class HeadersTableModel extends AbstractTableModel {
    private final List<HeaderKV> rows;
    private static final String[] COLS = {"Header", "Value"};

    public HeadersTableModel(List<HeaderKV> rows) { this.rows = rows; }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int col) { return COLS[col]; }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        HeaderKV kv = rows.get(rowIndex);
        return columnIndex == 0 ? kv.key : kv.value;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        HeaderKV kv = rows.get(rowIndex);
        if (columnIndex == 0) kv.key = aValue == null ? "" : aValue.toString();
        else kv.value = aValue == null ? "" : aValue.toString();
        fireTableCellUpdated(rowIndex, columnIndex);
    }

    @Override public boolean isCellEditable(int rowIndex, int columnIndex) { return true; }

    public void addRow() {
        rows.add(new HeaderKV("", ""));
        fireTableRowsInserted(rows.size()-1, rows.size()-1);
    }

    public void removeRow(int index) {
        if (index < 0 || index >= rows.size()) return;
        rows.remove(index);
        fireTableRowsDeleted(index, index);
    }
}
