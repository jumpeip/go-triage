package gotriage.ghidra;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTree;
import javax.swing.SpinnerNumberModel;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeWillExpandListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import docking.widgets.filechooser.GhidraFileChooser;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.util.Msg;
import gotriage.core.Category;
import gotriage.core.FuncInfo;
import gotriage.core.TriageResult;

/** Lazily expanded call tree with an actor-focused mode. */
final class CallGraphPanel extends JPanel {

	interface Host {
		TriageSession session();

		void navigate(long addr);

		void selectFunction(FuncInfo f);
	}

	private static final String ROOT_SELECTED = "Selected function";
	private static final String ROOT_ENTRIES = "Actor entry points";
	private static final String ROOT_ACTOR_ROOTS = "Actor roots (not called by actor code)";

	/** Tree node payload. */
	private static final class Item {
		final FuncInfo f;
		final String label;
		final int depth;
		final boolean group;
		final List<FuncInfo> groupMembers;
		final Set<Integer> path;

		Item(FuncInfo f, String label, int depth, Set<Integer> path) {
			this.f = f;
			this.label = label;
			this.depth = depth;
			this.group = false;
			this.groupMembers = null;
			this.path = path;
		}

		Item(String label, List<FuncInfo> members, int depth, Set<Integer> path) {
			this.f = null;
			this.label = label;
			this.depth = depth;
			this.group = true;
			this.groupMembers = members;
			this.path = path;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private static final Object LOADING = "...";

	private final Host host;
	private final JComboBox<String> direction = new JComboBox<>(new String[] { "Callees (calls made)", "Callers (who calls)" });
	private final JComboBox<String> rootMode = new JComboBox<>(new String[] { ROOT_SELECTED, ROOT_ENTRIES, ROOT_ACTOR_ROOTS });
	private final JCheckBox actorFocus = new JCheckBox("Actor focus", true);
	private final JSpinner maxDepth = new JSpinner(new SpinnerNumberModel(8, 1, 40, 1));
	private final JLabel title = new JLabel(" ");
	private final DefaultTreeModel model = new DefaultTreeModel(new DefaultMutableTreeNode("(no function selected)"));
	private final JTree tree = new JTree(model);
	private FuncInfo current;

	CallGraphPanel(Host host) {
		super(new BorderLayout());
		this.host = host;
		actorFocus.setToolTipText("Hide runtime and compiler-generated callees; fold stdlib/third-party calls into an 'API calls' node");
		JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		bar.add(new JLabel("Root:"));
		bar.add(rootMode);
		bar.add(direction);
		bar.add(actorFocus);
		bar.add(new JLabel("Max depth:"));
		bar.add(maxDepth);
		JButton expand = new JButton("Expand 3 levels");
		expand.addActionListener(e -> expandLevels(3));
		bar.add(expand);
		JButton dot = new JButton("Export DOT...");
		dot.setToolTipText("Write the actor call graph (from the current root) as Graphviz DOT");
		dot.addActionListener(e -> exportDot());
		bar.add(dot);
		JPanel north = new JPanel(new BorderLayout());
		north.add(bar, BorderLayout.NORTH);
		title.setFont(title.getFont().deriveFont(Font.BOLD));
		north.add(title, BorderLayout.SOUTH);
		add(north, BorderLayout.NORTH);
		add(new JScrollPane(tree), BorderLayout.CENTER);

		tree.setRootVisible(true);
		tree.setShowsRootHandles(true);
		tree.setCellRenderer(new Renderer());
		tree.addTreeWillExpandListener(new TreeWillExpandListener() {
			@Override
			public void treeWillExpand(TreeExpansionEvent e) {
				populate((DefaultMutableTreeNode) e.getPath().getLastPathComponent());
			}

			@Override
			public void treeWillCollapse(TreeExpansionEvent e) {
			}
		});
		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				TreePath p = tree.getPathForLocation(e.getX(), e.getY());
				if (p == null || !(((DefaultMutableTreeNode) p.getLastPathComponent()).getUserObject() instanceof Item it)
						|| it.f == null) {
					return;
				}
				if (e.getClickCount() == 2) {
					host.navigate(it.f.fn.entry());
					host.selectFunction(it.f);
				}
			}
		});
		direction.addActionListener(e -> rebuild());
		rootMode.addActionListener(e -> rebuild());
		actorFocus.addActionListener(e -> rebuild());
		maxDepth.addChangeListener(e -> rebuild());
	}

	void setFunction(FuncInfo f) {
		current = f;
		if (ROOT_SELECTED.equals(rootMode.getSelectedItem())) {
			rebuild();
		}
	}

	void rebuild() {
		TriageSession s = host.session();
		if (s == null) {
			model.setRoot(new DefaultMutableTreeNode("(run the analysis first)"));
			return;
		}
		String mode = (String) rootMode.getSelectedItem();
		DefaultMutableTreeNode root;
		if (ROOT_SELECTED.equals(mode)) {
			if (current == null) {
				model.setRoot(new DefaultMutableTreeNode("(select a function in the Functions tab or the listing)"));
				title.setText(" ");
				return;
			}
			root = node(current, 0, new HashSet<>());
			title.setText((callees() ? "Calls made by " : "Callers of ") + current.name());
		}
		else {
			List<FuncInfo> roots = ROOT_ENTRIES.equals(mode) ? s.result.entryPoints() : actorRoots(s.result);
			roots.sort(Comparator.comparing((FuncInfo f) -> -f.risk).thenComparing(FuncInfo::name));
			root = new DefaultMutableTreeNode(new Item(mode + " (" + roots.size() + ")", roots, -1, new HashSet<>()));
			for (FuncInfo f : roots) {
				root.add(node(f, 0, new HashSet<>()));
			}
			title.setText(mode + ": " + roots.size() + " functions");
		}
		model.setRoot(root);
		tree.expandPath(new TreePath(root.getPath()));
	}

	private static List<FuncInfo> actorRoots(TriageResult r) {
		List<FuncInfo> out = new ArrayList<>();
		for (FuncInfo f : r.funcs) {
			if (!f.isActor()) {
				continue;
			}
			boolean calledByActor = false;
			for (int c : f.callers) {
				if (r.funcs.get(c).isActor()) {
					calledByActor = true;
					break;
				}
			}
			if (!calledByActor) {
				out.add(f);
			}
		}
		return out;
	}

	private boolean callees() {
		return direction.getSelectedIndex() == 0;
	}

	private DefaultMutableTreeNode node(FuncInfo f, int depth, Set<Integer> path) {
		Set<Integer> p = new HashSet<>(path);
		p.add(f.index);
		DefaultMutableTreeNode n = new DefaultMutableTreeNode(new Item(f, label(f), depth, p));
		if (depth < (Integer) maxDepth.getValue() && !edges(f).isEmpty()) {
			n.add(new DefaultMutableTreeNode(LOADING));
		}
		return n;
	}

	private java.util.Collection<Integer> edges(FuncInfo f) {
		return callees() ? f.callees : f.callers;
	}

	private void populate(DefaultMutableTreeNode n) {
		if (n.getChildCount() != 1 || ((DefaultMutableTreeNode) n.getChildAt(0)).getUserObject() != LOADING) {
			return;
		}
		n.removeAllChildren();
		Object uo = n.getUserObject();
		if (!(uo instanceof Item it)) {
			return;
		}
		if (it.group) {
			for (FuncInfo m : it.groupMembers) {
				n.add(new DefaultMutableTreeNode(new Item(m, label(m), it.depth + 1, it.path)));
			}
			model.nodeStructureChanged(n);
			return;
		}
		TriageResult r = host.session().result;
		boolean focus = actorFocus.isSelected();
		List<FuncInfo> actorKids = new ArrayList<>();
		List<FuncInfo> apiKids = new ArrayList<>();
		for (int c : edges(it.f)) {
			FuncInfo cf = r.funcs.get(c);
			if (focus) {
				if (cf.category == Category.RUNTIME || cf.category == Category.GENERATED && !cf.isActorGenerated()) {
					continue;
				}
				if (cf.isActor() || cf.isActorGenerated()) {
					actorKids.add(cf);
				}
				else {
					apiKids.add(cf);
				}
			}
			else {
				actorKids.add(cf);
			}
		}
		actorKids.sort(Comparator.comparing((FuncInfo f) -> -f.risk).thenComparing(FuncInfo::name));
		apiKids.sort(Comparator.comparing(FuncInfo::name));
		for (FuncInfo cf : actorKids) {
			if (it.path.contains(cf.index)) {
				n.add(new DefaultMutableTreeNode(new Item(cf, label(cf) + "   (recursive)", it.depth + 1, it.path)));
			}
			else {
				n.add(node(cf, it.depth + 1, it.path));
			}
		}
		if (!apiKids.isEmpty()) {
			String what = callees() ? "library / API calls" : "library callers";
			DefaultMutableTreeNode g = new DefaultMutableTreeNode(
				new Item(what + " (" + apiKids.size() + ")", apiKids, it.depth, it.path));
			g.add(new DefaultMutableTreeNode(LOADING));
			n.add(g);
		}
		model.nodeStructureChanged(n);
	}

	private static String label(FuncInfo f) {
		StringBuilder b = new StringBuilder(f.name());
		if (f.risk > 0 && (f.isActor() || f.isActorGenerated())) {
			b.append("   [risk ").append(f.risk).append(']');
		}
		if (!f.caps.isEmpty()) {
			b.append("   {").append(String.join(",", f.caps.keySet())).append('}');
		}
		return b.toString();
	}

	private void expandLevels(int levels) {
		Object root = model.getRoot();
		if (root instanceof DefaultMutableTreeNode r) {
			expand(r, levels);
		}
	}

	private void expand(DefaultMutableTreeNode n, int levels) {
		if (levels < 0) {
			return;
		}
		TreePath p = new TreePath(n.getPath());
		populate(n);
		tree.expandPath(p);
		for (int i = 0; i < n.getChildCount(); i++) {
			DefaultMutableTreeNode c = (DefaultMutableTreeNode) n.getChildAt(i);
			if (c.getUserObject() instanceof Item it && !it.group) {
				expand(c, levels - 1);
			}
		}
	}

	// ------------------------------------------------------------------ DOT

	private void exportDot() {
		TriageSession s = host.session();
		if (s == null) {
			return;
		}
		List<FuncInfo> roots = new ArrayList<>();
		String mode = (String) rootMode.getSelectedItem();
		if (ROOT_SELECTED.equals(mode) && current != null) {
			roots.add(current);
		}
		else if (ROOT_ENTRIES.equals(mode)) {
			roots.addAll(s.result.entryPoints());
		}
		else {
			roots.addAll(actorRoots(s.result));
		}
		if (roots.isEmpty()) {
			Msg.showInfo(this, this, "Export DOT", "Nothing to export: select a function or another root.");
			return;
		}
		GhidraFileChooser fc = new GhidraFileChooser(this);
		fc.setTitle("Export actor call graph (DOT)");
		fc.setSelectedFile(new File(s.result.binaryName + "-actor-callgraph.dot"));
		File out = fc.getSelectedFile();
		if (out == null) {
			return;
		}
		try {
			Files.writeString(out.toPath(), dot(s.result, roots, (Integer) maxDepth.getValue()), StandardCharsets.UTF_8);
			Msg.info(this, "GoTriage: wrote " + out);
		}
		catch (Exception ex) {
			Msg.showError(this, this, "Export DOT", "Could not write " + out, ex);
		}
	}

	static String dot(TriageResult r, List<FuncInfo> roots, int depth) {
		StringBuilder b = new StringBuilder("digraph actor_calls {\n  rankdir=LR;\n  node [shape=box, fontname=\"Helvetica\", fontsize=10];\n");
		Map<Integer, Integer> seen = new LinkedHashMap<>();
		Deque<int[]> q = new ArrayDeque<>();
		for (FuncInfo f : roots) {
			q.add(new int[] { f.index, 0 });
		}
		Set<String> edges = new HashSet<>();
		while (!q.isEmpty()) {
			int[] cur = q.poll();
			if (seen.containsKey(cur[0])) {
				continue;
			}
			seen.put(cur[0], cur[1]);
			FuncInfo f = r.funcs.get(cur[0]);
			for (int c : f.callees) {
				FuncInfo cf = r.funcs.get(c);
				if (cf.category == Category.RUNTIME || cf.category == Category.GENERATED) {
					continue;
				}
				if (cf.isActor()) {
					edges.add("  n" + f.index + " -> n" + cf.index + ";");
					if (cur[1] + 1 <= depth) {
						q.add(new int[] { c, cur[1] + 1 });
					}
				}
				else if (!cf.caps.isEmpty() || calleeHasRule(cf)) {
					edges.add("  n" + f.index + " -> api" + cf.index + ";");
					b.append("  api").append(cf.index).append(" [label=\"").append(dotEsc(cf.name()))
							.append("\", shape=note, style=filled, fillcolor=\"#eeeeee\"];\n");
				}
			}
		}
		for (int i : seen.keySet()) {
			FuncInfo f = r.funcs.get(i);
			String color = f.risk >= 60 ? "#ffc4c4" : f.risk >= 30 ? "#ffe4b0" : "#c8ecc8";
			b.append("  n").append(i).append(" [label=\"").append(dotEsc(f.name()))
					.append(f.risk > 0 ? "\\nrisk " + f.risk : "")
					.append(f.caps.isEmpty() ? "" : "\\n" + dotEsc(String.join(",", f.caps.keySet())))
					.append("\", style=filled, fillcolor=\"").append(color).append("\"];\n");
		}
		for (String e : edges) {
			b.append(e).append('\n');
		}
		return b.append("}\n").toString();
	}

	private static boolean calleeHasRule(FuncInfo f) {
		return f.category == Category.THIRD_PARTY && f.libraryNote != null && !f.libraryNote.startsWith("library");
	}

	private static String dotEsc(String s) {
		return s.replace("\\", "\\\\").replace("\"", "\\\"");
	}

	/** Colours nodes by category. */
	private static final class Renderer extends DefaultTreeCellRenderer {
		@Override
		public Component getTreeCellRendererComponent(JTree t, Object v, boolean sel, boolean exp, boolean leaf, int row,
				boolean focus) {
			Component c = super.getTreeCellRendererComponent(t, v, sel, exp, leaf, row, focus);
			Object uo = ((DefaultMutableTreeNode) v).getUserObject();
			if (uo instanceof Item it) {
				if (it.f != null) {
					if (!sel) {
						setForeground(it.f.risk >= 60 ? Palette.RED : Renderers.categoryColor(it.f.category));
					}
					setFont(getFont().deriveFont(it.f.isActor() ? Font.BOLD : Font.PLAIN));
				}
				else {
					setFont(getFont().deriveFont(Font.ITALIC));
				}
			}
			return c;
		}
	}
}
