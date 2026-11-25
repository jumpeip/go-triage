package gotriage.ghidra;

import javax.swing.JComponent;

import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import resources.Icons;

/** Docking window hosting the {@link TriagePanel}. */
public final class GoTriageProvider extends ComponentProviderAdapter implements TriagePanel.Host {

	private final GoTriagePlugin plugin;
	private final TriagePanel panel;

	public GoTriageProvider(GoTriagePlugin plugin) {
		super(plugin.getTool(), "Go Triage", plugin.getName());
		this.plugin = plugin;
		setTitle("Go Triage");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setIcon(Icons.INFO_ICON);
		panel = new TriagePanel(this);
		createActions();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	TriagePanel panel() {
		return panel;
	}

	void setSession(TriageSession s) {
		panel.setSession(s);
	}

	void locationChanged(Address a) {
		panel.locationChanged(a);
	}

	private void createActions() {
		add(new ActionBuilder("Go Triage Analyze", plugin.getName())
				.toolBarIcon(Icons.REFRESH_ICON)
				.description("Analyze (or re-analyze) the current program's Go metadata; reloads the knowledge base")
				.onAction(c -> plugin.analyze(true))
				.build());
		add(new ActionBuilder("Go Triage Apply Markup", plugin.getName())
				.toolBarIcon(Icons.MAKE_SELECTION_ICON)
				.description("Apply functions, names, namespaces, tags, bookmarks, colours and comments to the program")
				.onAction(c -> panel.applyMarkupDialog())
				.build());
		add(new ActionBuilder("Go Triage Clear Markup", plugin.getName())
				.toolBarIcon(Icons.CLEAR_ICON)
				.description("Remove GoTriage bookmarks, tags, plate comments and colours")
				.onAction(c -> plugin.clearMarkup())
				.build());
		add(new ActionBuilder("Go Triage Export", plugin.getName())
				.toolBarIcon(Icons.SAVE_AS_ICON)
				.description("Export a JSON / CSV / Markdown report, YARA rule or DOT call graph")
				.onAction(c -> panel.exportDialog())
				.build());
		add(new ActionBuilder("Go Triage Knowledge Base", plugin.getName())
				.toolBarIcon(Icons.OPEN_FOLDER_ICON)
				.description("Show where the editable knowledge-base files are loaded from")
				.onAction(c -> panel.showKnowledgeBase())
				.build());
		add(new ActionBuilder("Go Triage Help", plugin.getName())
				.toolBarIcon(Icons.HELP_ICON)
				.description("How Go Triage classifies code")
				.onAction(c -> panel.showHelp())
				.build());
	}

	private void add(DockingAction a) {
		addLocalAction(a);
	}

	// ------------------------------------------------------------------ TriagePanel.Host

	@Override
	public void goTo(long addr) {
		plugin.goTo(addr);
	}

	@Override
	public void analyze(boolean reloadKnowledge) {
		plugin.analyze(reloadKnowledge);
	}

	@Override
	public void applyMarkup(MarkupApplier.Options o) {
		plugin.applyMarkup(o);
	}

	@Override
	public void clearMarkup() {
		plugin.clearMarkup();
	}

	@Override
	public MarkupApplier.Options markupOptions() {
		return plugin.markupOptions();
	}

	@Override
	public void subtitle(String s) {
		setSubTitle(s);
	}
}
