package com.gqlasa.ui.querybuilder;

import com.gqlasa.model.PathRow;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class PathsTableModel extends AbstractTableModel {
    private final List<PathRow> all = new ArrayList<>();
    private final List<PathRow> page = new ArrayList<>();

    private int pageSize = 25;
    private int pageIndex = 0;

    public void setData(List<PathRow> rows) {
        all.clear();
        if (rows != null) all.addAll(rows);
        pageIndex = 0;
        refreshPage();
    }

    public void setPageSize(int size) {
        this.pageSize = Math.max(1, size);
        pageIndex = 0;
        refreshPage();
    }

    public int getPageIndex() { return pageIndex; }
    public int getPageCount() {
        if (all.isEmpty()) return 1;
        return (int) Math.ceil(all.size() / (double) pageSize);
    }

    public void nextPage() { if (pageIndex + 1 < getPageCount()) { pageIndex++; refreshPage(); } }
    public void prevPage() { if (pageIndex > 0) { pageIndex--; refreshPage(); } }

    public PathRow getRowAt(int tableRow) {
        if (tableRow < 0 || tableRow >= page.size()) return null;
        return page.get(tableRow);
    }

    private void refreshPage() {
        page.clear();
        int start = pageIndex * pageSize;
        int end = Math.min(all.size(), start + pageSize);
        for (int i = start; i < end; i++) page.add(all.get(i));
        fireTableDataChanged();
    }

    @Override public int getRowCount() { return page.size(); }
    @Override public int getColumnCount() { return 5; }

    @Override
    public String getColumnName(int column) {
        return switch (column) {
            case 0 -> "Index";
            case 1 -> "Path";
            case 2 -> "Root field";
            case 3 -> "Depth";
            case 4 -> "Has required args";
            default -> "";
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        PathRow r = page.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> r.index;
            case 1 -> r.pathText;
            case 2 -> r.rootField;
            case 3 -> r.depth;
            case 4 -> r.hasRequiredArgs ? "Yes" : "No";
            default -> "";
        };
    }

    @Override public boolean isCellEditable(int rowIndex, int columnIndex) { return false; }
}
