package gotriage.ghidra;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

/** Declarative table model: rows of T, columns defined by getter lambdas. */
public final class ColumnModel<T> extends AbstractTableModel {

	/** One column. {@code width} is the preferred width in pixels. */
	public record Col<T>(String name, Class<?> type, Function<T, Object> get, int width, String tip) {
		public Col(String name, Class<?> type, Function<T, Object> get, int width) {
			this(name, type, get, width, null);
		}
	}

	private final List<Col<T>> cols;
	private List<T> rows = new ArrayList<>();

	@SafeVarargs
	public ColumnModel(Col<T>... cols) {
		this.cols = List.of(cols);
	}

	public void setRows(List<T> rows) {
		this.rows = new ArrayList<>(rows);
		fireTableDataChanged();
	}

	public List<T> rows() {
		return rows;
	}

	public T row(int modelRow) {
		return modelRow >= 0 && modelRow < rows.size() ? rows.get(modelRow) : null;
	}

	public int indexOf(T t) {
		return rows.indexOf(t);
	}

	@Override
	public int getRowCount() {
		return rows.size();
	}

	@Override
	public int getColumnCount() {
		return cols.size();
	}

	@Override
	public String getColumnName(int c) {
		return cols.get(c).name();
	}

	@Override
	public Class<?> getColumnClass(int c) {
		return cols.get(c).type();
	}

	@Override
	public Object getValueAt(int r, int c) {
		T t = row(r);
		return t == null ? null : cols.get(c).get().apply(t);
	}

	public Col<T> col(int c) {
		return cols.get(c);
	}

	/** Applies the preferred widths to a table that uses this model. */
	public void applyWidths(JTable table) {
		for (int i = 0; i < cols.size() && i < table.getColumnModel().getColumnCount(); i++) {
			TableColumn tc = table.getColumnModel().getColumn(i);
			tc.setPreferredWidth(cols.get(i).width());
		}
	}
}
