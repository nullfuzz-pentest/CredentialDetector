package creddetector;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/** Table model for the detections. */
public class DetectionTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "#", "Time", "Method", "Host", "URL", "Matches", "Terms"
    };

    private final List<Detection> rows = new ArrayList<>();

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int col) {
        return COLUMNS[col];
    }

    @Override
    public Class<?> getColumnClass(int col) {
        if (col == 0 || col == 5) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public Object getValueAt(int row, int col) {
        Detection d = rows.get(row);
        switch (col) {
            case 0: return row + 1;
            case 1: return d.timestamp;
            case 2: return d.method;
            case 3: return d.host;
            case 4: return d.url;
            case 5: return d.count;
            case 6: return d.terms;
            default: return "";
        }
    }

    public void addDetection(Detection detection) {
        rows.add(detection);
        int idx = rows.size() - 1;
        fireTableRowsInserted(idx, idx);
    }

    public Detection getDetection(int row) {
        if (row >= 0 && row < rows.size()) {
            return rows.get(row);
        }
        return null;
    }

    public void clear() {
        rows.clear();
        fireTableDataChanged();
    }

    public int count() {
        return rows.size();
    }

    public List<Detection> getRows() {
        return rows;
    }
}
