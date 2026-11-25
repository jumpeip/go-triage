package gotriage.ghidra;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import gotriage.cli.RawImage;
import gotriage.core.FuncInfo;
import gotriage.core.KnowledgeBase;
import gotriage.core.Progress;
import gotriage.core.TriageEngine;
import gotriage.core.TriageResult;

/**
 * Offscreen GUI test: drives the real {@link TriagePanel} with real analysis results and writes
 * one PNG per tab/state. Not part of the extension.
 *
 * usage: GuiHarness <binary> <outDir> [kbDir]
 */
public final class GuiHarness {

	public static void main(String[] args) throws Exception {
		Path bin = Path.of(args[0]);
		File out = new File(args[1]);
		out.mkdirs();
		KnowledgeBase kb = KnowledgeBase.load(args.length > 2 ? Path.of(args[2]) : null);
		TriageResult r = TriageEngine.run(new RawImage(bin), kb, null, true, bin.getFileName().toString(), Progress.NONE);
		TriageSession s = TriageSession.detached(r, kb);
		System.out.println("analysis ok: " + r.funcs.size() + " functions, " + r.actorFunctions().size() + " actor");

		SwingUtilities.invokeAndWait(() -> {
			try {
				run(s, out);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		System.exit(0);
	}

	private static void run(TriageSession s, File out) throws Exception {
		TriagePanel p = new TriagePanel(new TriagePanel.Host() {
			@Override
			public void goTo(long addr) {
				System.out.println("  host.goTo 0x" + Long.toHexString(addr));
			}

			@Override
			public void analyze(boolean reload) {
			}

			@Override
			public void applyMarkup(MarkupApplier.Options o) {
			}

			@Override
			public void clearMarkup() {
			}

			@Override
			public MarkupApplier.Options markupOptions() {
				return new MarkupApplier.Options();
			}

			@Override
			public void subtitle(String t) {
				System.out.println("  subtitle: " + t);
			}
		});
		JFrame f = new JFrame("harness");
		f.setUndecorated(true);
		f.getContentPane().add(p);
		f.pack();
		f.setSize(new Dimension(1500, 860));
		f.validate();

		p.setSession(s);
		JTabbedPane tabs = field(p, "tabs", JTabbedPane.class);
		JTable fn = field(p, "fnTable", JTable.class);
		JTextField search = field(p, "search", JTextField.class);
		@SuppressWarnings("unchecked")
		JComboBox<String> view = field(p, "view", JComboBox.class);

		shot(f, p, tabs, 0, out, "01-overview");
		System.out.println("functions (actor view): " + fn.getRowCount());
		if (fn.getRowCount() > 0) {
			fn.getSelectionModel().setSelectionInterval(0, 0);
		}
		shot(f, p, tabs, 1, out, "02-functions-actor");

		view.setSelectedItem("Everything");
		System.out.println("functions (everything): " + fn.getRowCount());
		search.setText("tag:panic-path");
		System.out.println("functions (tag:panic-path): " + fn.getRowCount());
		search.setText("cap:EXEC");
		view.setSelectedItem("Likely actor code");
		System.out.println("functions (actor, cap:EXEC): " + fn.getRowCount());
		shot(f, p, tabs, 1, out, "03-functions-cap-exec");
		search.setText("");

		shot(f, p, tabs, 2, out, "04-packages");
		JCheckBox tagged = field(p, "strTaggedOnly", JCheckBox.class);
		tagged.setSelected(true);
		invoke(p, "refilter");
		System.out.println("strings (actor, tagged): " + field(p, "strTable", JTable.class).getRowCount());
		shot(f, p, tabs, 3, out, "05-strings");
		System.out.println("types (actor view): " + field(p, "typeTable", JTable.class).getRowCount());
		shot(f, p, tabs, 4, out, "06-types");

		FuncInfo main = s.result.byName("main.main");
		FuncInfo target = main;
		List<FuncInfo> actor = s.result.actorFunctions();
		actor.sort((a, b) -> b.risk - a.risk);
		if (!actor.isEmpty()) {
			target = actor.get(0);
		}
		p.selectFunction(target);
		System.out.println("xrefs for " + target.name() + ": callers=" + field(p, "callerTable", JTable.class).getRowCount()
			+ " callees=" + field(p, "calleeTable", JTable.class).getRowCount());
		shot(f, p, tabs, 5, out, "07-xrefs");

		CallGraphPanel g = field(p, "graph", CallGraphPanel.class);
		if (main != null) {
			g.setFunction(main);
		}
		Method expand = CallGraphPanel.class.getDeclaredMethod("expandLevels", int.class);
		expand.setAccessible(true);
		expand.invoke(g, 3);
		shot(f, p, tabs, 6, out, "08-callgraph");
		shot(f, p, tabs, 7, out, "09-build");
		shot(f, p, tabs, 8, out, "10-yara");
		f.dispose();
	}

	private static void shot(JFrame f, TriagePanel p, JTabbedPane tabs, int tab, File out, String name) throws Exception {
		tabs.setSelectedIndex(tab);
		f.validate();
		layoutAll(p);
		BufferedImage img = new BufferedImage(p.getWidth(), p.getHeight(), BufferedImage.TYPE_INT_RGB);
		Graphics2D g = img.createGraphics();
		p.printAll(g);
		g.dispose();
		ImageIO.write(img, "png", new File(out, name + ".png"));
	}

	private static void layoutAll(Component c) {
		c.doLayout();
		if (c instanceof Container ct) {
			for (Component k : ct.getComponents()) {
				layoutAll(k);
			}
		}
	}

	private static <T> T field(Object o, String name, Class<T> type) throws Exception {
		Field fl = o.getClass().getDeclaredField(name);
		fl.setAccessible(true);
		return type.cast(fl.get(o));
	}

	private static void invoke(Object o, String name) throws Exception {
		Method m = o.getClass().getDeclaredMethod(name);
		m.setAccessible(true);
		m.invoke(o);
	}
}
