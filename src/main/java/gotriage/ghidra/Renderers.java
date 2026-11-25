package gotriage.ghidra;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;

import generic.theme.GThemeDefaults.Colors.Palette;
import gotriage.core.Category;

/** Cell renderers shared by the Go Triage tables. */
final class Renderers {

	private Renderers() {
	}

	static Color categoryColor(Category c) {
		return switch (c) {
			case ACTOR -> Palette.GREEN;
			case UNKNOWN -> Palette.TEAL;
			case THIRD_PARTY -> Palette.BLUE;
			case STDLIB -> Palette.GRAY;
			case RUNTIME -> Palette.GRAY;
			case GENERATED -> Palette.PURPLE;
		};
	}

	/** Hex rendering for Long addresses (sorting stays numeric). */
	static final class Hex extends DefaultTableCellRenderer {
		Hex() {
			setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		}

		@Override
		protected void setValue(Object v) {
			setText(v instanceof Long l ? "0x" + Long.toHexString(l) : v == null ? "" : v.toString());
		}
	}

	/** Coloured, bold-for-actor category text. */
	static final class Cat extends DefaultTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
			JLabel l = (JLabel) super.getTableCellRendererComponent(t, v, sel, focus, r, c);
			if (v instanceof Category cat) {
				l.setText(cat.label);
				if (!sel) {
					l.setForeground(categoryColor(cat));
				}
				l.setFont(l.getFont().deriveFont(cat.isActorLike() ? Font.BOLD : Font.PLAIN));
			}
			return l;
		}
	}

	/** Risk heat: number on a background that warms with the score. */
	static final class Risk extends DefaultTableCellRenderer {
		Risk() {
			setHorizontalAlignment(SwingConstants.RIGHT);
		}

		@Override
		public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
			JLabel l = (JLabel) super.getTableCellRendererComponent(t, v, sel, focus, r, c);
			if (!sel) {
				int risk = v instanceof Integer i ? i : 0;
				l.setForeground(risk >= 60 ? Palette.RED : risk >= 30 ? Palette.ORANGE : risk > 0 ? t.getForeground() : Palette.GRAY);
				l.setFont(l.getFont().deriveFont(risk >= 30 ? Font.BOLD : Font.PLAIN));
			}
			return l;
		}
	}

	/** Numbers right-aligned, zero greyed. */
	static final class Num extends DefaultTableCellRenderer {
		Num() {
			setHorizontalAlignment(SwingConstants.RIGHT);
		}

		@Override
		public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
			JLabel l = (JLabel) super.getTableCellRendererComponent(t, v, sel, focus, r, c);
			if (!sel && v instanceof Number n && n.longValue() == 0) {
				l.setForeground(Palette.GRAY);
			}
			return l;
		}
	}
}
