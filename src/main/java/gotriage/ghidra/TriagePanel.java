package gotriage.ghidra;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SpinnerNumberModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.TableRowSorter;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.util.Msg;
import ghidra.util.Swing;
import gotriage.core.Bytes;
import gotriage.core.Category;
import gotriage.core.FuncInfo;
import gotriage.core.GoBuildInfo;
import gotriage.core.GoTypes;
import gotriage.core.KnowledgeBase;
import gotriage.core.PackageInfo;
import gotriage.core.Reports;
import gotriage.core.StringInfo;
import gotriage.core.TriageResult;
import gotriage.core.YaraGenerator;

/**
 * The Go Triage user interface. Independent of the docking framework so it can be hosted by
 * {@link GoTriageProvider} inside Ghidra or rendered by a test harness.
 */
public final class TriagePanel extends JPanel implements CallGraphPanel.Host {

	/** Operations the panel delegates to its host (the plugin in Ghidra). */
	public interface Host {
		void goTo(long addr);

		void analyze(boolean reloadKnowledge);

		void applyMarkup(MarkupApplier.Options o);

		void clearMarkup();

		MarkupApplier.Options markupOptions();

		void subtitle(String s);
	}


	private static final String VIEW_ACTOR = "Likely actor code";
	private static final String VIEW_ACTOR_3P = "Actor + third-party";
	private static final String VIEW_NO_NOISE = "Everything except runtime/generated";
	private static final String VIEW_ALL = "Everything";
	private static final String VIEW_CUSTOM = "Custom";

	private final Host host;
	private final JPanel root = new JPanel(new BorderLayout());
	private TriageSession session;

	// ---------------------------------------------------------------- filter bar
	private final JComboBox<String> view =
		new JComboBox<>(new String[] { VIEW_ACTOR, VIEW_ACTOR_3P, VIEW_NO_NOISE, VIEW_ALL, VIEW_CUSTOM });
	private final Map<Category, JCheckBox> catBoxes = new HashMap<>();
	private final JCheckBox actorGenerated = new JCheckBox("+ generated code of actor packages");
	private final JSpinner minConf = new JSpinner(new SpinnerNumberModel(0, 0, 100, 5));
	private final JSpinner minRisk = new JSpinner(new SpinnerNumberModel(0, 0, 100, 5));
	private final JComboBox<String> capFilter = new JComboBox<>(new String[] { "(any capability)" });
	private final JTextField search = new JTextField(24);
	private boolean suppressFilterEvents;

	// ---------------------------------------------------------------- tabs
	private final JTabbedPane tabs = new JTabbedPane();
	private final JEditorPane overview = htmlPane();
	private final JEditorPane detail = htmlPane();
	private final JLabel status = new JLabel(" ");

	private final ColumnModel<FuncInfo> fnModel = new ColumnModel<>(
		new ColumnModel.Col<>("Address", Long.class, f -> f.fn.entry(), 95),
		new ColumnModel.Col<>("Category", Category.class, f -> f.category, 80),
		new ColumnModel.Col<>("Actor", Boolean.class, FuncInfo::isActor, 42),
		new ColumnModel.Col<>("Conf", Integer.class, f -> f.actorConfidence, 42),
		new ColumnModel.Col<>("Risk", Integer.class, f -> f.risk, 42),
		new ColumnModel.Col<>("Package", String.class, FuncInfo::packagePath, 220),
		new ColumnModel.Col<>("Function", String.class, f -> f.sym.shortName(), 220),
		new ColumnModel.Col<>("Capabilities", String.class, f -> String.join(", ", f.allCaps()), 220),
		new ColumnModel.Col<>("Why", String.class, TriagePanel::why, 300),
		new ColumnModel.Col<>("Source", String.class, FuncInfo::sourceLocation, 200),
		new ColumnModel.Col<>("Size", Long.class, f -> f.fn.size(), 55),
		new ColumnModel.Col<>("Callers", Integer.class, f -> f.callers.size(), 50),
		new ColumnModel.Col<>("Callees", Integer.class, f -> f.callees.size(), 50),
		new ColumnModel.Col<>("Noise calls", Integer.class, f -> f.noiseCalls, 60),
		new ColumnModel.Col<>("Tags", String.class, f -> String.join(", ", f.tags), 160));
	private final JTable fnTable = new JTable(fnModel);
	private final TableRowSorter<ColumnModel<FuncInfo>> fnSorter = new TableRowSorter<>(fnModel);

	private final ColumnModel<PackageInfo> pkgModel = new ColumnModel<>(
		new ColumnModel.Col<>("Package", String.class, p -> p.path, 280),
		new ColumnModel.Col<>("Category", Category.class, p -> p.category, 85),
		new ColumnModel.Col<>("Conf", Integer.class, p -> p.confidence, 42),
		new ColumnModel.Col<>("Functions", Integer.class, p -> p.funcs.size(), 60),
		new ColumnModel.Col<>("Actor fns", Integer.class, p -> p.actorFuncs, 60),
		new ColumnModel.Col<>("Max risk", Integer.class, p -> p.maxRisk, 55),
		new ColumnModel.Col<>("KB", Long.class, p -> p.codeBytes / 1024, 50),
		new ColumnModel.Col<>("Capabilities", String.class, p -> String.join(", ", p.caps), 220),
		new ColumnModel.Col<>("Module", String.class, PackageInfo::moduleLabel, 200),
		new ColumnModel.Col<>("Why", String.class, p -> String.join("; ", p.reasons), 360));
	private final JTable pkgTable = new JTable(pkgModel);
	private final TableRowSorter<ColumnModel<PackageInfo>> pkgSorter = new TableRowSorter<>(pkgModel);

	private final ColumnModel<StringInfo> strModel = new ColumnModel<>(
		new ColumnModel.Col<>("Address", Long.class, s -> s.address, 95),
		new ColumnModel.Col<>("String", String.class, s -> s.value.replace("\n", "\\n").replace("\r", "\\r"), 420),
		new ColumnModel.Col<>("Tags", String.class, s -> String.join(", ", s.tags), 140),
		new ColumnModel.Col<>("Capabilities", String.class, s -> String.join(", ", s.caps), 140),
		new ColumnModel.Col<>("Refs", Integer.class, s -> s.referencedBy.size(), 40),
		new ColumnModel.Col<>("Referrer category", Category.class, s -> s.bestCategory(session.result), 90),
		new ColumnModel.Col<>("Referenced by", String.class, this::referrers, 300),
		new ColumnModel.Col<>("Exact len", Boolean.class, s -> s.exactLength, 55));
	private final JTable strTable = new JTable(strModel);
	private final TableRowSorter<ColumnModel<StringInfo>> strSorter = new TableRowSorter<>(strModel);
	private final JCheckBox strTaggedOnly = new JCheckBox("Indicators only (tagged strings)");

	private final ColumnModel<GoTypes.GoType> typeModel = new ColumnModel<>(
		new ColumnModel.Col<>("Address", Long.class, t -> t.address, 95),
		new ColumnModel.Col<>("Type", String.class, t -> t.name, 280),
		new ColumnModel.Col<>("Kind", String.class, GoTypes.GoType::kindName, 70),
		new ColumnModel.Col<>("Size", Long.class, t -> t.size, 50),
		new ColumnModel.Col<>("Used by", Integer.class, t -> typeUsers(t).size(), 55),
		new ColumnModel.Col<>("Fields", String.class, t -> String.join("; ", t.fields), 500));
	private final JTable typeTable = new JTable(typeModel);
	private final TableRowSorter<ColumnModel<GoTypes.GoType>> typeSorter = new TableRowSorter<>(typeModel);
	private Map<Long, List<Integer>> typeUsersIndex = new HashMap<>();

	private final ColumnModel<FuncInfo> callerModel = xrefModel();
	private final ColumnModel<FuncInfo> calleeModel = xrefModel();
	private final JTable callerTable = new JTable(callerModel);
	private final JTable calleeTable = new JTable(calleeModel);
	private final JCheckBox xrefHideNoise = new JCheckBox("Hide runtime / compiler noise", true);
	private final JCheckBox followListing = new JCheckBox("Follow listing location", true);
	private final JLabel xrefTitle = new JLabel(" ");
	private FuncInfo xrefFunc;

	private final ColumnModel<GoBuildInfo.Module> depModel = new ColumnModel<>(
		new ColumnModel.Col<>("Module", String.class, GoBuildInfo.Module::path, 300),
		new ColumnModel.Col<>("Version", String.class, GoBuildInfo.Module::version, 140),
		new ColumnModel.Col<>("Class", String.class, this::depClass, 80),
		new ColumnModel.Col<>("Functions", Integer.class, this::depFuncs, 60),
		new ColumnModel.Col<>("Note", String.class, this::depNote, 300),
		new ColumnModel.Col<>("Replaced by", String.class, GoBuildInfo.Module::replacedBy, 200),
		new ColumnModel.Col<>("Sum", String.class, GoBuildInfo.Module::sum, 260));
	private final JTable depTable = new JTable(depModel);
	private final ColumnModel<String[]> settingModel = new ColumnModel<>(
		new ColumnModel.Col<>("Setting", String.class, a -> a[0], 160),
		new ColumnModel.Col<>("Value", String.class, a -> a[1], 600));
	private final JTable settingTable = new JTable(settingModel);

	private final JTextArea yara = new JTextArea();
	private final CallGraphPanel graph = new CallGraphPanel(this);

	public TriagePanel(Host host) {
		super(new BorderLayout());
		this.host = host;
		build();
		add(root, BorderLayout.CENTER);
		setSession(null);
	}

	@Override
	public TriageSession session() {
		return session;
	}

	// ================================================================ layout

	private static JEditorPane htmlPane() {
		JEditorPane p = new JEditorPane("text/html", "");
		p.setEditable(false);
		return p;
	}

	private void build() {
		root.add(filterBar(), BorderLayout.NORTH);
		tabs.addTab("Overview", new JScrollPane(overview));
		tabs.addTab("Functions", functionsTab());
		tabs.addTab("Packages", tablePanel(pkgTable, pkgModel, pkgSorter, null));
		tabs.addTab("Strings", stringsTab());
		tabs.addTab("Types", tablePanel(typeTable, typeModel, typeSorter, null));
		tabs.addTab("Xrefs", xrefTab());
		tabs.addTab("Call Graph", graph);
		tabs.addTab("Build / Modules", buildTab());
		tabs.addTab("YARA", yaraTab());
		root.add(tabs, BorderLayout.CENTER);
		status.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
		root.add(status, BorderLayout.SOUTH);
		root.setPreferredSize(new Dimension(1200, 520));

		for (JEditorPane p : new JEditorPane[] { overview, detail }) {
			p.addHyperlinkListener(e -> {
				if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
					link(e.getDescription());
				}
			});
		}
		tabs.addChangeListener(e -> updateStatus());
	}

	private JComponent filterBar() {
		JPanel p = new JPanel();
		p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
		JPanel r1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		r1.add(new JLabel("View:"));
		r1.add(view);
		for (Category c : Category.values()) {
			JCheckBox cb = new JCheckBox(c.label);
			cb.setToolTipText(c.description);
			cb.setForeground(Renderers.categoryColor(c));
			catBoxes.put(c, cb);
			r1.add(cb);
			cb.addActionListener(e -> {
				if (!suppressFilterEvents) {
					suppressFilterEvents = true;
					view.setSelectedItem(VIEW_CUSTOM);
					suppressFilterEvents = false;
					refilter();
				}
			});
		}
		r1.add(actorGenerated);
		actorGenerated.setToolTipText("Also show type eq/hash routines and wrappers that belong to actor packages");
		JPanel r2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		r2.add(new JLabel("Min confidence:"));
		r2.add(minConf);
		r2.add(new JLabel("Min risk:"));
		r2.add(minRisk);
		r2.add(new JLabel("Capability:"));
		r2.add(capFilter);
		r2.add(new JLabel("Filter:"));
		search.setToolTipText("<html>Substring over name, package, source, capabilities and tags.<br>"
				+ "Prefixes: <b>pkg:</b>path, <b>cap:</b>NAME, <b>tag:</b>name, <b>re:</b>regex");
		r2.add(search);
		JButton clear = new JButton("Reset");
		clear.addActionListener(e -> {
			search.setText("");
			minConf.setValue(0);
			minRisk.setValue(0);
			capFilter.setSelectedIndex(0);
			view.setSelectedItem(VIEW_ACTOR);
		});
		r2.add(clear);
		p.add(r1);
		p.add(r2);

		view.addActionListener(e -> {
			if (!suppressFilterEvents) {
				applyView();
			}
		});
		actorGenerated.addActionListener(e -> refilter());
		minConf.addChangeListener(e -> refilter());
		minRisk.addChangeListener(e -> refilter());
		capFilter.addActionListener(e -> refilter());
		search.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				refilter();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				refilter();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				refilter();
			}
		});
		applyView();
		return p;
	}

	private void applyView() {
		String v = (String) view.getSelectedItem();
		Set<Category> on = switch (v) {
			case VIEW_ACTOR -> EnumSet.of(Category.ACTOR, Category.UNKNOWN);
			case VIEW_ACTOR_3P -> EnumSet.of(Category.ACTOR, Category.UNKNOWN, Category.THIRD_PARTY);
			case VIEW_NO_NOISE -> EnumSet.of(Category.ACTOR, Category.UNKNOWN, Category.THIRD_PARTY, Category.STDLIB);
			case VIEW_ALL -> EnumSet.allOf(Category.class);
			default -> null;
		};
		if (on != null) {
			suppressFilterEvents = true;
			for (Map.Entry<Category, JCheckBox> e : catBoxes.entrySet()) {
				e.getValue().setSelected(on.contains(e.getKey()));
			}
			suppressFilterEvents = false;
		}
		refilter();
	}

	private JComponent functionsTab() {
		setupTable(fnTable, fnModel, fnSorter);
		fnTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				FuncInfo f = selected(fnTable, fnModel);
				if (f != null) {
					showDetail(f);
				}
			}
		});
		onDoubleClick(fnTable, fnModel, f -> {
			navigate(f.fn.entry());
			focusFunction(f, false);
		});
		fnTable.setComponentPopupMenu(functionPopup());
		JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(fnTable), new JScrollPane(detail));
		sp.setResizeWeight(0.6);
		return sp;
	}

	private JPopupMenu functionPopup() {
		JPopupMenu m = new JPopupMenu();
		m.add(item("Go to function", () -> withSelected(f -> navigate(f.fn.entry()))));
		m.add(item("Show in Xrefs", () -> withSelected(f -> {
			focusFunction(f, false);
			tabs.setSelectedIndex(5);
		})));
		m.add(item("Show call graph", () -> withSelected(f -> {
			focusFunction(f, false);
			tabs.setSelectedIndex(6);
		})));
		m.addSeparator();
		m.add(item("Mark as actor code", () -> override(Boolean.TRUE)));
		m.add(item("Mark as NOT actor code", () -> override(Boolean.FALSE)));
		m.add(item("Clear analyst override", () -> override(null)));
		m.addSeparator();
		m.add(item("Filter to this package", () -> withSelected(f -> search.setText("pkg:" + f.packagePath()))));
		m.add(item("Copy name", () -> withSelected(f -> copy(f.name()))));
		m.add(item("Copy explanation", () -> withSelected(f -> copy(MarkupApplier.plate(f)))));
		return m;
	}

	private static JMenuItem item(String text, Runnable r) {
		JMenuItem i = new JMenuItem(text);
		i.addActionListener(e -> r.run());
		return i;
	}

	private void withSelected(Consumer<FuncInfo> c) {
		FuncInfo f = selected(fnTable, fnModel);
		if (f != null) {
			c.accept(f);
		}
	}

	private void override(Boolean v) {
		if (session == null) {
			return;
		}
		int[] rows = fnTable.getSelectedRows();
		for (int r : rows) {
			FuncInfo f = fnModel.row(fnTable.convertRowIndexToModel(r));
			if (f != null) {
				f.override = v;
			}
		}
		session.saveOverrides();
		fnModel.fireTableDataChanged();
		refilter();
	}

	private JComponent stringsTab() {
		JPanel extra = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		extra.add(strTaggedOnly);
		extra.add(new JLabel("Strings are shown when a referencing function passes the category filter."));
		strTaggedOnly.addActionListener(e -> refilter());
		JComponent p = tablePanel(strTable, strModel, strSorter, extra);
		onDoubleClick(strTable, strModel, s -> navigate(s.address));
		JPopupMenu m = new JPopupMenu();
		m.add(item("Copy string", () -> {
			StringInfo s = selected(strTable, strModel);
			if (s != null) {
				copy(s.value);
			}
		}));
		m.add(item("Show first referencing function", () -> {
			StringInfo s = selected(strTable, strModel);
			if (s != null && !s.referencedBy.isEmpty()) {
				FuncInfo f = session.result.funcs.get(s.referencedBy.iterator().next());
				selectFunction(f);
			}
		}));
		strTable.setComponentPopupMenu(m);
		return p;
	}

	private JComponent tablePanel(JTable t, ColumnModel<?> m, TableRowSorter<?> sorter, JComponent extra) {
		setupTable(t, m, sorter);
		if (t == pkgTable) {
			onDoubleClick(pkgTable, pkgModel, p -> {
				search.setText("pkg:" + p.path);
				if (!catBoxes.get(p.category).isSelected()) {
					view.setSelectedItem(VIEW_ALL);
				}
				tabs.setSelectedIndex(1);
			});
		}
		if (t == typeTable) {
			onDoubleClick(typeTable, typeModel, ty -> navigate(ty.address));
		}
		JPanel p = new JPanel(new BorderLayout());
		if (extra != null) {
			p.add(extra, BorderLayout.NORTH);
		}
		p.add(new JScrollPane(t), BorderLayout.CENTER);
		return p;
	}

	private static ColumnModel<FuncInfo> xrefModel() {
		return new ColumnModel<>(
			new ColumnModel.Col<>("Address", Long.class, f -> f.fn.entry(), 95),
			new ColumnModel.Col<>("Category", Category.class, f -> f.category, 80),
			new ColumnModel.Col<>("Risk", Integer.class, f -> f.risk, 42),
			new ColumnModel.Col<>("Function", String.class, FuncInfo::name, 380),
			new ColumnModel.Col<>("Capabilities", String.class, f -> String.join(", ", f.caps.keySet()), 200));
	}

	private JComponent xrefTab() {
		for (JTable t : new JTable[] { callerTable, calleeTable }) {
			@SuppressWarnings("unchecked")
			ColumnModel<FuncInfo> m = (ColumnModel<FuncInfo>) t.getModel();
			setupTable(t, m, new TableRowSorter<>(m));
			onDoubleClick(t, m, f -> {
				navigate(f.fn.entry());
				focusFunction(f, true);
			});
		}
		JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		bar.add(followListing);
		bar.add(xrefHideNoise);
		xrefHideNoise.addActionListener(e -> showXrefs(xrefFunc));
		xrefTitle.setFont(xrefTitle.getFont().deriveFont(Font.BOLD));
		bar.add(Box.createHorizontalStrut(12));
		bar.add(xrefTitle);
		JPanel left = new JPanel(new BorderLayout());
		left.add(new JLabel(" Callers (double-click to walk up)"), BorderLayout.NORTH);
		left.add(new JScrollPane(callerTable), BorderLayout.CENTER);
		JPanel right = new JPanel(new BorderLayout());
		right.add(new JLabel(" Callees (double-click to walk down)"), BorderLayout.NORTH);
		right.add(new JScrollPane(calleeTable), BorderLayout.CENTER);
		JSplitPane sp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
		sp.setResizeWeight(0.5);
		JPanel p = new JPanel(new BorderLayout());
		p.add(bar, BorderLayout.NORTH);
		p.add(sp, BorderLayout.CENTER);
		return p;
	}

	private JComponent buildTab() {
		setupTable(settingTable, settingModel, new TableRowSorter<>(settingModel));
		setupTable(depTable, depModel, new TableRowSorter<>(depModel));
		JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(settingTable), new JScrollPane(depTable));
		sp.setResizeWeight(0.35);
		return sp;
	}

	private JComponent yaraTab() {
		yara.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		JButton regen = new JButton("Regenerate");
		regen.addActionListener(e -> {
			if (session != null) {
				yara.setText(YaraGenerator.generate(session.result, null));
			}
		});
		JButton copyB = new JButton("Copy");
		copyB.addActionListener(e -> copy(yara.getText()));
		JButton save = new JButton("Save...");
		save.addActionListener(e -> saveText(yara.getText(), ".yar"));
		bar.add(regen);
		bar.add(copyB);
		bar.add(save);
		bar.add(new JLabel("Draft rule from actor function names, indicator strings and module/build paths - review before use."));
		JPanel p = new JPanel(new BorderLayout());
		p.add(bar, BorderLayout.NORTH);
		p.add(new JScrollPane(yara), BorderLayout.CENTER);
		return p;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void setupTable(JTable t, ColumnModel<?> m, TableRowSorter sorter) {
		t.setRowSorter(sorter);
		t.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		t.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		t.setFillsViewportHeight(true);
		t.setDefaultRenderer(Category.class, new Renderers.Cat());
		t.setDefaultRenderer(Long.class, new Renderers.Num());
		t.setDefaultRenderer(Integer.class, new Renderers.Num());
		m.applyWidths(t);
		for (int i = 0; i < m.getColumnCount(); i++) {
			String n = m.getColumnName(i);
			if (n.equals("Address")) {
				t.getColumnModel().getColumn(i).setCellRenderer(new Renderers.Hex());
			}
			else if (n.equals("Risk") || n.equals("Max risk")) {
				t.getColumnModel().getColumn(i).setCellRenderer(new Renderers.Risk());
			}
		}
	}

	private static <T> void onDoubleClick(JTable t, ColumnModel<T> m, Consumer<T> c) {
		t.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					int r = t.rowAtPoint(e.getPoint());
					if (r >= 0) {
						T row = m.row(t.convertRowIndexToModel(r));
						if (row != null) {
							c.accept(row);
						}
					}
				}
			}
		});
	}

	private static <T> T selected(JTable t, ColumnModel<T> m) {
		int r = t.getSelectedRow();
		return r < 0 ? null : m.row(t.convertRowIndexToModel(r));
	}

	// ================================================================ actions

	void applyMarkupDialog() {
		if (session == null) {
			Msg.showInfo(this, root, "Go Triage", "Run the analysis first.");
			return;
		}
		MarkupApplier.Options o = host.markupOptions();
		JCheckBox create = new JCheckBox("Create missing functions from pclntab (" + session.missingFunctions + " missing)", o.createFunctions);
		JCheckBox chunks = new JCheckBox("Merge Ghidra function fragments back into pclntab owners (" + session.chunks.size() + ")", o.fixChunks);
		JCheckBox rename = new JCheckBox("Rename functions to their Go names (user-defined names are kept)", o.rename);
		JComboBox<MarkupApplier.NamespaceMode> ns = new JComboBox<>(MarkupApplier.NamespaceMode.values());
		ns.setSelectedItem(o.namespaces);
		JCheckBox nsActor = new JCheckBox("Namespaces for actor code only", o.namespacesActorOnly);
		JCheckBox tags = new JCheckBox("Function tags (GO_ACTOR, GO_STDLIB, GO_CAP_EXEC, ...)", o.tags);
		JCheckBox bm = new JCheckBox("Bookmarks on actor functions and indicator strings", o.bookmarks);
		JSpinner thr = new JSpinner(new SpinnerNumberModel(o.bookmarkRiskThreshold, 0, 100, 5));
		JCheckBox col = new JCheckBox("Background colours on actor code (green / orange / red by risk)", o.colors);
		JCheckBox com = new JCheckBox("Plate comments with the explanation on actor functions", o.comments);
		JCheckBox str = new JCheckBox("Define Go string literals referenced by actor code", o.defineStrings);
		JPanel p = new JPanel(new GridLayout(0, 1, 2, 2));
		p.add(create);
		p.add(chunks);
		p.add(rename);
		JPanel nsp = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
		nsp.add(new JLabel("Namespaces:"));
		nsp.add(ns);
		p.add(nsp);
		p.add(nsActor);
		p.add(tags);
		p.add(bm);
		JPanel tp = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
		tp.add(new JLabel("Risk threshold for WARNING bookmarks / GO_SUSPICIOUS tag / orange colour:"));
		tp.add(thr);
		p.add(tp);
		p.add(col);
		p.add(com);
		p.add(str);
		int rc = JOptionPane.showConfirmDialog(root, p, "Go Triage - apply markup", JOptionPane.OK_CANCEL_OPTION,
			JOptionPane.PLAIN_MESSAGE);
		if (rc != JOptionPane.OK_OPTION) {
			return;
		}
		o.createFunctions = create.isSelected();
		o.fixChunks = chunks.isSelected();
		o.rename = rename.isSelected();
		o.namespaces = (MarkupApplier.NamespaceMode) ns.getSelectedItem();
		o.namespacesActorOnly = nsActor.isSelected();
		o.tags = tags.isSelected();
		o.bookmarks = bm.isSelected();
		o.bookmarkRiskThreshold = (Integer) thr.getValue();
		o.colors = col.isSelected();
		o.comments = com.isSelected();
		o.defineStrings = str.isSelected();
		host.applyMarkup(o);
	}

	void exportDialog() {
		if (session == null) {
			Msg.showInfo(this, root, "Go Triage", "Run the analysis first.");
			return;
		}
		JComboBox<String> fmt = new JComboBox<>(new String[] { "JSON (full report)", "CSV (functions)",
			"Markdown (summary)", "YARA (draft rule)", "DOT (actor call graph)" });
		JCheckBox actorOnly = new JCheckBox("Likely actor code only (JSON / CSV)", false);
		JPanel p = new JPanel(new GridLayout(0, 1));
		p.add(fmt);
		p.add(actorOnly);
		if (JOptionPane.showConfirmDialog(root, p, "Go Triage - export", JOptionPane.OK_CANCEL_OPTION,
			JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) {
			return;
		}
		TriageResult r = session.result;
		switch (fmt.getSelectedIndex()) {
			case 0 -> saveText(Reports.json(r, actorOnly.isSelected()), ".json");
			case 1 -> saveText(Reports.csv(r, actorOnly.isSelected()), ".csv");
			case 2 -> saveText(Reports.markdown(r, 50), ".md");
			case 3 -> saveText(YaraGenerator.generate(r, null), ".yar");
			default -> saveText(CallGraphPanel.dot(r, r.entryPoints().isEmpty() ? r.actorFunctions() : r.entryPoints(), 12), ".dot");
		}
	}

	private void saveText(String text, String ext) {
		GhidraFileChooser fc = new GhidraFileChooser(root);
		fc.setTitle("Save " + ext + " file");
		String base = session == null ? "go-triage" : session.result.binaryName;
		fc.setSelectedFile(new File(base + "-gotriage" + ext));
		File f = fc.getSelectedFile();
		if (f == null) {
			return;
		}
		try {
			Files.writeString(f.toPath(), text, StandardCharsets.UTF_8);
			Msg.info(this, "GoTriage: wrote " + f);
			status.setText("Saved " + f);
		}
		catch (Exception ex) {
			Msg.showError(this, root, "Go Triage", "Could not write " + f, ex);
		}
	}

	void showKnowledgeBase() {
		StringBuilder b = new StringBuilder("<html>Knowledge-base files are loaded from the first folder that has them:<ol>");
		for (java.nio.file.Path d : TriageSession.knowledgeDirs()) {
			b.append("<li>").append(Html.esc(d.toString())).append(Files.isDirectory(d) ? "" : " <i>(does not exist)</i>")
					.append("</li>");
		}
		b.append("<li>bundled defaults inside the extension jar</li></ol>");
		b.append("Copy any of <b>").append(String.join(", ", KnowledgeBase.FILES))
				.append("</b> from the extension's data folder into the first folder to customise it,<br>")
				.append("then press <b>Analyze</b> to reload. Formats are documented at the top of each file.</html>");
		Msg.showInfo(this, root, "Go Triage knowledge base", b.toString());
	}

	void showHelp() {
		String h = "<html><body style='width:640px'>"
				+ "<h3>Go Triage</h3>"
				+ "<p>Recovers Go metadata straight from the binary (pclntab, build info, moduledata, type descriptors) "
				+ "and sorts every function into <b>Actor</b>, <b>Unknown</b> (likely actor), <b>Third-party</b>, "
				+ "<b>Stdlib</b>, <b>Runtime</b> or <b>Generated</b>.</p>"
				+ "<p><b>Attribution evidence</b>, strongest first: build-info main module vs dependency modules; "
				+ "pclntab source paths (GOROOT, module cache <code>/pkg/mod/</code> or <code>@vX</code>, vendor, "
				+ "or a local source tree on the author's machine); the known-library knowledge base. "
				+ "Compiler output is recognised from <code>&lt;autogenerated&gt;</code> files, the runtime wrapper funcID, "
				+ "<code>-fm</code> method values and <code>type:.eq/.hash</code> routines.</p>"
				+ "<p><b>Risk</b> sums capability weights inferred from the APIs a function calls, the libraries it uses "
				+ "and the strings it references, plus indirect capabilities reached through other actor functions "
				+ "and bonuses for suspicious combinations (e.g. network + exec). Every point is explained in the "
				+ "detail pane, the plate comment and the exports.</p>"
				+ "<p><b>Tips</b>: filter with <code>pkg:</code>, <code>cap:</code>, <code>tag:</code> or <code>re:</code>; "
				+ "right-click a function to override the verdict (saved in the program); "
				+ "the Call Graph's actor focus hides runtime/compiler noise and folds library calls into one node.</p>"
				+ "</body></html>";
		Msg.showInfo(this, root, "Go Triage help", h);
	}

	// ================================================================ data

	void setSession(TriageSession s) {
		this.session = s;
		if (s == null) {
			overview.setText("<html><body style='font-family:sans-serif;padding:8px'><h3>Go Triage</h3>"
					+ "<p>Press the <b>Analyze</b> button (refresh icon) to triage the current program.</p>"
					+ "<p>Works on unanalysed programs too: Go metadata is read straight from the bytes. "
					+ "After Ghidra auto-analysis, its references are merged in for better call and string coverage.</p>"
					+ "</body></html>");
			fnModel.setRows(List.of());
			pkgModel.setRows(List.of());
			strModel.setRows(List.of());
			typeModel.setRows(List.of());
			depModel.setRows(List.of());
			settingModel.setRows(List.of());
			callerModel.setRows(List.of());
			calleeModel.setRows(List.of());
			detail.setText("");
			yara.setText("");
			graph.rebuild();
			host.subtitle("");
			updateStatus();
			return;
		}
		TriageResult r = s.result;
		host.subtitle(r.binaryName + " - " + r.goVersion());
		overview.setText(Html.overview(s));
		overview.setCaretPosition(0);
		fnModel.setRows(Reports.triageOrder(r));
		pkgModel.setRows(new ArrayList<>(r.packages.values()));
		strModel.setRows(new ArrayList<>(r.strings.values()));
		typeUsersIndex = new HashMap<>();
		for (FuncInfo f : r.funcs) {
			for (long t : f.typeRefs) {
				typeUsersIndex.computeIfAbsent(t, k -> new ArrayList<>()).add(f.index);
			}
		}
		// actor-defined types first (package qualifier is an actor package name), then by usage
		Set<String> actorPkgNames = new java.util.HashSet<>();
		for (PackageInfo pi : r.packages.values()) {
			if (pi.category.isActorLike() && !pi.path.isEmpty()) {
				actorPkgNames.add(pi.path.substring(pi.path.lastIndexOf('/') + 1));
			}
		}
		List<GoTypes.GoType> types = r.types == null ? new ArrayList<>() : new ArrayList<>(r.types.all().values());
		types.sort(Comparator.comparing((GoTypes.GoType t) -> !actorPkgNames.contains(t.packageName()))
				.thenComparing(t -> -typeUsers(t).size())
				.thenComparing(t -> t.name));
		typeModel.setRows(types);
		// packages: actor first, then by size
		List<PackageInfo> pkgs = new ArrayList<>(r.packages.values());
		pkgs.sort(Comparator.comparing((PackageInfo pi) -> pi.category.ordinal()).thenComparing(pi -> -pi.maxRisk)
				.thenComparing(pi -> pi.path));
		pkgModel.setRows(pkgs);
		List<GoBuildInfo.Module> deps = new ArrayList<>();
		List<String[]> settings = new ArrayList<>();
		if (r.buildInfo != null) {
			if (r.buildInfo.mainModule != null) {
				deps.add(r.buildInfo.mainModule);
			}
			deps.addAll(r.buildInfo.deps);
			settings.add(new String[] { "go version", r.buildInfo.goVersion });
			settings.add(new String[] { "path", r.buildInfo.mainPackagePath });
			for (Map.Entry<String, String> e : r.buildInfo.settings.entrySet()) {
				settings.add(new String[] { e.getKey(), e.getValue() });
			}
		}
		else {
			settings.add(new String[] { "build info", "absent" });
		}
		settings.add(new String[] { "GOROOT (from paths)", r.goroot == null ? "?" : r.goroot });
		settings.add(new String[] { "trimpath", String.valueOf(r.trimpath) });
		settings.add(new String[] { "build users", String.join(", ", r.buildUsers) });
		settings.add(new String[] { "garble suspected", r.garbleSuspected ? "yes: " + r.garbleEvidence : "no" });
		depModel.setRows(deps);
		settingModel.setRows(settings);

		Set<String> caps = new TreeSet<>();
		for (FuncInfo f : r.funcs) {
			caps.addAll(f.caps.keySet());
		}
		suppressFilterEvents = true;
		capFilter.removeAllItems();
		capFilter.addItem("(any capability)");
		for (String c : caps) {
			capFilter.addItem(c);
		}
		suppressFilterEvents = false;
		yara.setText(YaraGenerator.generate(r, null));
		xrefFunc = null;
		showXrefs(null);
		FuncInfo main = r.byName("main.main");
		if (main != null) {
			graph.setFunction(main);
		}
		else {
			graph.rebuild();
		}
		refilter();
		tabs.setSelectedIndex(0);
	}

	private static String why(FuncInfo f) {
		List<String> all = new ArrayList<>();
		if (!f.attributionReasons.isEmpty()) {
			all.add(f.attributionReasons.get(0));
		}
		int n = 0;
		for (String r : f.riskReasons) {
			if (r.startsWith("Pattern") || r.startsWith("Offensive")) {
				all.add(0, r);
			}
			else if (n++ < 2) {
				all.add(r);
			}
		}
		return String.join(" | ", all);
	}

	private String referrers(StringInfo s) {
		if (session == null) {
			return "";
		}
		List<String> n = new ArrayList<>();
		for (int i : s.referencedBy) {
			n.add(session.result.funcs.get(i).name());
			if (n.size() >= 3) {
				break;
			}
		}
		String t = String.join(", ", n);
		return s.referencedBy.size() > 3 ? t + ", ... (+" + (s.referencedBy.size() - 3) + ")" : t;
	}

	private List<Integer> typeUsers(GoTypes.GoType t) {
		return typeUsersIndex.getOrDefault(t.address, List.of());
	}

	private String depClass(GoBuildInfo.Module d) {
		if (session == null || d.path() == null) {
			return "";
		}
		if (session.result.buildInfo != null && d == session.result.buildInfo.mainModule) {
			return "MAIN";
		}
		KnowledgeBase.Library l = session.kb.libraryFor(d.path());
		return l == null ? "unknown" : l.libClass();
	}

	private String depNote(GoBuildInfo.Module d) {
		if (session == null || d.path() == null) {
			return "";
		}
		KnowledgeBase.Library l = session.kb.libraryFor(d.path());
		return l == null ? "" : l.description();
	}

	private Integer depFuncs(GoBuildInfo.Module d) {
		if (session == null || d.path() == null) {
			return 0;
		}
		int n = 0;
		for (PackageInfo p : session.result.packages.values()) {
			if (p.path.equals(d.path()) || p.path.startsWith(d.path() + "/")) {
				n += p.funcs.size();
			}
		}
		return n;
	}

	// ================================================================ filtering

	private Set<Category> enabledCategories() {
		Set<Category> s = EnumSet.noneOf(Category.class);
		for (Map.Entry<Category, JCheckBox> e : catBoxes.entrySet()) {
			if (e.getValue().isSelected()) {
				s.add(e.getKey());
			}
		}
		return s;
	}

	/** Compiled search term. */
	private record Query(String pkg, String cap, String tag, Pattern re, String text) {
		static Query parse(String s) {
			String t = s.strip();
			if (t.isEmpty()) {
				return new Query(null, null, null, null, null);
			}
			String low = t.toLowerCase(Locale.ROOT);
			if (low.startsWith("pkg:")) {
				return new Query(t.substring(4).strip(), null, null, null, null);
			}
			if (low.startsWith("cap:")) {
				return new Query(null, t.substring(4).strip().toUpperCase(Locale.ROOT), null, null, null);
			}
			if (low.startsWith("tag:")) {
				return new Query(null, null, t.substring(4).strip(), null, null);
			}
			if (low.startsWith("re:")) {
				try {
					return new Query(null, null, null, Pattern.compile(t.substring(3), Pattern.CASE_INSENSITIVE), null);
				}
				catch (PatternSyntaxException e) {
					return new Query(null, null, null, null, low);
				}
			}
			return new Query(null, null, null, null, low);
		}

		boolean matches(String... fields) {
			if (re != null) {
				for (String f : fields) {
					if (f != null && re.matcher(f).find()) {
						return true;
					}
				}
				return false;
			}
			if (text == null) {
				return true;
			}
			for (String f : fields) {
				if (f != null && f.toLowerCase(Locale.ROOT).contains(text)) {
					return true;
				}
			}
			return false;
		}
	}

	private boolean functionVisible(FuncInfo f, Set<Category> cats, boolean withGen) {
		boolean catOk = cats.contains(f.category)
				|| (f.override != null && f.override && (cats.contains(Category.ACTOR)))
				|| (withGen && f.isActorGenerated());
		if (f.override != null && !f.override && !cats.contains(f.category)) {
			catOk = false;
		}
		return catOk;
	}

	void refilter() {
		if (suppressFilterEvents) {
			return;
		}
		Set<Category> cats = enabledCategories();
		boolean withGen = actorGenerated.isSelected();
		int mc = (Integer) minConf.getValue();
		int mr = (Integer) minRisk.getValue();
		String cap = capFilter.getSelectedIndex() <= 0 ? null : (String) capFilter.getSelectedItem();
		Query q = Query.parse(search.getText());

		fnSorter.setRowFilter(new RowFilter<>() {
			@Override
			public boolean include(Entry<? extends ColumnModel<FuncInfo>, ? extends Integer> e) {
				FuncInfo f = e.getModel().row(e.getIdentifier());
				if (f == null || !functionVisible(f, cats, withGen)) {
					return false;
				}
				if (f.actorConfidence < mc || f.risk < mr) {
					return false;
				}
				if (cap != null && !f.caps.containsKey(cap) && !f.transitiveCaps.containsKey(cap)) {
					return false;
				}
				if (q.pkg() != null && !(f.packagePath().equals(q.pkg()) || f.packagePath().startsWith(q.pkg() + "/"))) {
					return false;
				}
				if (q.cap() != null && !f.caps.containsKey(q.cap()) && !f.transitiveCaps.containsKey(q.cap())) {
					return false;
				}
				if (q.tag() != null && !f.tags.contains(q.tag())) {
					return false;
				}
				return q.matches(f.name(), f.sourceLocation(), String.join(" ", f.allCaps()), String.join(" ", f.tags));
			}
		});

		pkgSorter.setRowFilter(new RowFilter<>() {
			@Override
			public boolean include(Entry<? extends ColumnModel<PackageInfo>, ? extends Integer> e) {
				PackageInfo p = e.getModel().row(e.getIdentifier());
				if (p == null || !cats.contains(p.category) && !(p.actorFuncs > 0 && cats.contains(Category.ACTOR))) {
					return false;
				}
				if (p.confidence < mc || p.maxRisk < mr) {
					return false;
				}
				if (cap != null && !p.caps.contains(cap)) {
					return false;
				}
				if (q.pkg() != null && !(p.path.equals(q.pkg()) || p.path.startsWith(q.pkg() + "/"))) {
					return false;
				}
				return q.matches(p.path, String.join(" ", p.caps), p.moduleLabel());
			}
		});

		boolean taggedOnly = strTaggedOnly.isSelected();
		strSorter.setRowFilter(new RowFilter<>() {
			@Override
			public boolean include(Entry<? extends ColumnModel<StringInfo>, ? extends Integer> e) {
				StringInfo s = e.getModel().row(e.getIdentifier());
				if (s == null || session == null || (taggedOnly && s.tags.isEmpty())) {
					return false;
				}
				if (cap != null && !s.caps.contains(cap)) {
					return false;
				}
				boolean any = false;
				for (int i : s.referencedBy) {
					FuncInfo f = session.result.funcs.get(i);
					if (functionVisible(f, cats, withGen)
							&& (q.pkg() == null || f.packagePath().equals(q.pkg()) || f.packagePath().startsWith(q.pkg() + "/"))) {
						any = true;
						break;
					}
				}
				return any && q.matches(s.value, String.join(" ", s.tags), String.join(" ", s.caps));
			}
		});

		typeSorter.setRowFilter(new RowFilter<>() {
			@Override
			public boolean include(Entry<? extends ColumnModel<GoTypes.GoType>, ? extends Integer> e) {
				GoTypes.GoType t = e.getModel().row(e.getIdentifier());
				if (t == null || session == null) {
					return false;
				}
				List<Integer> users = typeUsers(t);
				boolean any = users.isEmpty() && cats.size() == Category.values().length;
				for (int i : users) {
					if (functionVisible(session.result.funcs.get(i), cats, withGen)) {
						any = true;
						break;
					}
				}
				return any && q.matches(t.name, String.join(" ", t.fields));
			}
		});
		updateStatus();
	}

	private void updateStatus() {
		if (session == null) {
			status.setText("No analysis yet.");
			return;
		}
		String tab = tabs.getTitleAt(Math.max(0, tabs.getSelectedIndex()));
		String counts = switch (tab) {
			case "Functions" -> fnTable.getRowCount() + " of " + fnModel.getRowCount() + " functions";
			case "Packages" -> pkgTable.getRowCount() + " of " + pkgModel.getRowCount() + " packages";
			case "Strings" -> strTable.getRowCount() + " of " + strModel.getRowCount() + " strings";
			case "Types" -> typeTable.getRowCount() + " of " + typeModel.getRowCount() + " types";
			default -> fnTable.getRowCount() + " functions match the filter";
		};
		status.setText(counts + "   |   " + session.result.actorFunctions().size() + " likely-actor functions of "
				+ session.result.funcs.size() + "   |   view: " + view.getSelectedItem());
	}

	// ================================================================ navigation / selection

	private void link(String desc) {
		if (desc == null || session == null) {
			return;
		}
		if (desc.startsWith("fn:")) {
			try {
				FuncInfo f = session.result.funcs.get(Integer.parseInt(desc.substring(3)));
				selectFunction(f);
				navigate(f.fn.entry());
			}
			catch (RuntimeException e) {
				// ignore
			}
		}
		else if (desc.startsWith("addr:")) {
			try {
				navigate(Long.parseUnsignedLong(desc.substring(5), 16));
			}
			catch (NumberFormatException e) {
				// ignore
			}
		}
	}

	@Override
	public void navigate(long addr) {
		host.goTo(addr);
	}

	/** Selects a function in the Functions tab (widening the view if it is filtered out). */
	@Override
	public void selectFunction(FuncInfo f) {
		if (f == null) {
			return;
		}
		int mi = fnModel.indexOf(f);
		if (mi < 0) {
			return;
		}
		int vi = fnTable.convertRowIndexToView(mi);
		if (vi < 0) {
			search.setText("");
			view.setSelectedItem(VIEW_ALL);
			vi = fnTable.convertRowIndexToView(mi);
		}
		if (vi >= 0) {
			fnTable.getSelectionModel().setSelectionInterval(vi, vi);
			fnTable.scrollRectToVisible(fnTable.getCellRect(vi, 0, true));
		}
		showDetail(f);
		focusFunction(f, false);
	}

	private void showDetail(FuncInfo f) {
		if (session == null) {
			return;
		}
		detail.setText(Html.function(session, f));
		detail.setCaretPosition(0);
	}

	private void focusFunction(FuncInfo f, boolean alsoSelect) {
		showXrefs(f);
		graph.setFunction(f);
		if (alsoSelect) {
			int mi = fnModel.indexOf(f);
			int vi = mi < 0 ? -1 : fnTable.convertRowIndexToView(mi);
			if (vi >= 0) {
				fnTable.getSelectionModel().setSelectionInterval(vi, vi);
				fnTable.scrollRectToVisible(fnTable.getCellRect(vi, 0, true));
			}
		}
	}

	private void showXrefs(FuncInfo f) {
		xrefFunc = f;
		if (f == null || session == null) {
			xrefTitle.setText("(select a function)");
			callerModel.setRows(List.of());
			calleeModel.setRows(List.of());
			return;
		}
		boolean hide = xrefHideNoise.isSelected();
		callerModel.setRows(xrefRows(f.callers, hide));
		calleeModel.setRows(xrefRows(f.callees, hide));
		int hiddenCallees = f.callees.size() - calleeModel.getRowCount();
		xrefTitle.setText(f.name() + "   [" + f.category.label + ", risk " + f.risk + "]"
				+ (hide && hiddenCallees > 0 ? "   (" + hiddenCallees + " noise callees hidden)" : ""));
	}

	private List<FuncInfo> xrefRows(java.util.Collection<Integer> idx, boolean hideNoise) {
		List<FuncInfo> out = new ArrayList<>();
		for (int i : idx) {
			FuncInfo f = session.result.funcs.get(i);
			if (hideNoise && (f.category == Category.RUNTIME || f.category == Category.GENERATED && !f.isActorGenerated())) {
				continue;
			}
			out.add(f);
		}
		out.sort(Comparator.comparing((FuncInfo x) -> !x.isActor()).thenComparing(x -> -x.risk)
				.thenComparing(FuncInfo::name));
		return out;
	}

	/** Called by the plugin when the listing location changes. */
	void locationChanged(ghidra.program.model.address.Address a) {
		if (session == null || !followListing.isSelected() || a == null) {
			return;
		}
		FuncInfo f = session.funcAt(a);
		if (f != null && f != xrefFunc) {
			Swing.runLater(() -> focusFunction(f, false));
		}
	}

	private static void copy(String s) {
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s), null);
	}

	/** For tests / scripts: currently visible function rows. */
	List<FuncInfo> visibleFunctions() {
		List<FuncInfo> out = new ArrayList<>();
		for (int i = 0; i < fnTable.getRowCount(); i++) {
			out.add(fnModel.row(fnTable.convertRowIndexToModel(i)));
		}
		return out;
	}

	@SuppressWarnings("unused")
	private static Set<String> set(String... s) {
		return new LinkedHashSet<>(List.of(s));
	}
}
