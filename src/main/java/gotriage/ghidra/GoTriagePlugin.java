/* ###
 * GoTriage - Go binary triage for Ghidra.
 *
 * Licensed under the Apache License, Version 2.0.
 */
package gotriage.ghidra;

import java.util.HashMap;
import java.util.Map;

import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.MiscellaneousPluginPackage;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import gotriage.core.KnowledgeBase;
import gotriage.core.TriageEngine;

/**
 * Go binary triage: separates actor-written code from the Go runtime, standard library,
 * third-party modules and compiler-generated code, and explains why.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Go Triage",
	description = "Recovers Go symbols from the pclntab, build info and moduledata, labels runtime, " +
		"standard-library, third-party and compiler-generated functions, and highlights likely actor " +
		"code with capabilities, confidence, risk and explanations. Applies namespaces, tags, " +
		"bookmarks, colours and comments.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class GoTriagePlugin extends ProgramPlugin {

	static final String MENU = "Go Triage";

	private GoTriageProvider provider;
	private final Map<Program, TriageSession> sessions = new HashMap<>();
	private final MarkupApplier.Options markupOptions = new MarkupApplier.Options();
	private KnowledgeBase kb;

	public GoTriagePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		provider = new GoTriageProvider(this);
		new ActionBuilder("Show Go Triage", getName())
				.menuPath("&Window", "Go Triage")
				.menuGroup("Go", "1")
				.description("Show the Go Triage window")
				.onAction(c -> showProvider())
				.buildAndInstall(tool);
		new ActionBuilder("Run Go Triage", getName())
				.menuPath("&Analysis", "Go Triage", "Analyze Go Binary")
				.menuGroup("Go", "1")
				.description("Triage the Go binary: actor code vs runtime / stdlib / third-party / generated")
				.enabledWhen(c -> currentProgram != null)
				.onAction(c -> {
					showProvider();
					analyze(true);
				})
				.buildAndInstall(tool);
		new ActionBuilder("Apply Go Triage Markup", getName())
				.menuPath("&Analysis", "Go Triage", "Apply Markup (defaults)")
				.menuGroup("Go", "2")
				.description("Analyze if needed, then apply functions/names/namespaces/tags/bookmarks/colours/comments")
				.enabledWhen(c -> currentProgram != null)
				.onAction(c -> {
					if (sessions.get(currentProgram) == null) {
						analyze(false, () -> applyMarkup(markupOptions));
					}
					else {
						applyMarkup(markupOptions);
					}
				})
				.buildAndInstall(tool);
	}

	GoTriageProvider provider() {
		return provider;
	}

	MarkupApplier.Options markupOptions() {
		return markupOptions;
	}

	private void showProvider() {
		provider.setVisible(true);
		provider.toFront();
		if (currentProgram != null && sessions.get(currentProgram) == null) {
			analyze(false);
		}
	}

	// ------------------------------------------------------------------ program events

	@Override
	protected void programActivated(Program program) {
		provider.setSession(sessions.get(program));
	}

	@Override
	protected void programClosed(Program program) {
		sessions.remove(program);
		if (program == currentProgram) {
			provider.setSession(null);
		}
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (loc != null && provider.isVisible()) {
			provider.locationChanged(loc.getAddress());
		}
	}

	// ------------------------------------------------------------------ operations

	/** Runs the triage on the current program (modal progress dialog). */
	void analyze(boolean reloadKnowledge) {
		analyze(reloadKnowledge, null);
	}

	/** As {@link #analyze(boolean)}, then runs {@code after} on the Swing thread on success. */
	void analyze(boolean reloadKnowledge, Runnable after) {
		Program program = currentProgram;
		if (program == null) {
			Msg.showInfo(this, provider.getComponent(), "Go Triage", "Open a program first.");
			return;
		}
		if (kb == null || reloadKnowledge) {
			kb = TriageSession.loadKnowledge();
		}
		KnowledgeBase knowledge = kb;
		Task task = new Task("Go Triage: " + program.getName(), true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					TriageSession s = TriageSession.run(program, knowledge, true, monitor);
					sessions.put(program, s);
					Swing.runLater(() -> {
						if (program == currentProgram) {
							provider.setSession(s);
							if (after != null) {
								after.run();
							}
						}
					});
					Msg.info(GoTriagePlugin.this, String.format("GoTriage: %s %s - %d functions, %d likely actor",
						program.getName(), s.result.goVersion(), s.result.funcs.size(),
						s.result.actorFunctions().size()));
				}
				catch (TriageEngine.NotGoBinaryException e) {
					Swing.runLater(() -> Msg.showInfo(GoTriagePlugin.this, provider.getComponent(), "Go Triage",
						program.getName() + ": " + e.getMessage()));
				}
			}
		};
		new TaskLauncher(task, provider.getComponent(), 500);
	}

	void applyMarkup(MarkupApplier.Options o) {
		TriageSession s = sessions.get(currentProgram);
		if (s == null) {
			return;
		}
		ColorizingService colorizer = tool.getService(ColorizingService.class);
		Task task = new Task("Go Triage: apply markup", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				MarkupApplier m = new MarkupApplier(s, o, colorizer);
				m.apply(monitor);
				for (String line : m.log()) {
					Msg.info(GoTriagePlugin.this, "GoTriage: " + line);
				}
				Swing.runLater(() -> provider.setSession(s));
			}
		};
		new TaskLauncher(task, provider.getComponent(), 500);
	}

	void clearMarkup() {
		TriageSession s = sessions.get(currentProgram);
		if (s == null) {
			return;
		}
		ColorizingService colorizer = tool.getService(ColorizingService.class);
		Task task = new Task("Go Triage: clear markup", true, false, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				MarkupApplier.clear(s, colorizer, monitor);
			}
		};
		new TaskLauncher(task, provider.getComponent(), 500);
	}

	void goTo(long offset) {
		if (currentProgram == null) {
			return;
		}
		GoToService gs = tool.getService(GoToService.class);
		Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		if (gs != null) {
			gs.goTo(a, currentProgram);
		}
	}

	@Override
	protected void dispose() {
		sessions.clear();
		if (provider != null) {
			provider.setVisible(false);
		}
		super.dispose();
	}
}
