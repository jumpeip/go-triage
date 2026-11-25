package gotriage.ghidra;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import gotriage.core.FuncInfo;
import gotriage.core.KnowledgeBase;
import gotriage.core.Progress;
import gotriage.core.RefCollector;
import gotriage.core.TriageEngine;
import gotriage.core.TriageResult;

/** A triage run bound to one Ghidra program. */
public final class TriageSession {

	public static final String MODULE = "GoTriage";
	static final String OPTIONS = "GoTriage";
	static final String OVERRIDES_KEY = "Analyst overrides";

	public final Program program;
	public final ProgramMemoryReader mem;
	public final TriageResult result;
	public final KnowledgeBase kb;
	/** Ghidra functions whose entry is inside a pclntab function but not at its entry. */
	public final List<Function> chunks = new ArrayList<>();
	/** pclntab functions without a Ghidra function at their entry. */
	public int missingFunctions;
	public int ghidraRefs;

	private TriageSession(Program program, ProgramMemoryReader mem, TriageResult result, KnowledgeBase kb) {
		this.program = program;
		this.mem = mem;
		this.result = result;
		this.kb = kb;
	}

	/** Knowledge-base search path: user settings folder, then the extension's data folder. */
	public static List<Path> knowledgeDirs() {
		List<Path> dirs = new ArrayList<>();
		try {
			File user = new File(Application.getUserSettingsDirectory(), MODULE);
			dirs.add(user.toPath());
		}
		catch (RuntimeException e) {
			// ignore
		}
		try {
			ResourceFile root = Application.getModuleRootDir(MODULE);
			if (root != null) {
				dirs.add(new File(root.getFile(false), "data").toPath());
			}
		}
		catch (RuntimeException e) {
			// not installed as a module (e.g. running from a script directory)
		}
		return dirs;
	}

	public static KnowledgeBase loadKnowledge() {
		KnowledgeBase kb = KnowledgeBase.load(knowledgeDirs());
		for (String w : kb.loadWarnings) {
			Msg.warn(TriageSession.class, "GoTriage knowledge base: " + w);
		}
		return kb;
	}

	public static TriageSession run(Program program, KnowledgeBase kb, boolean useGhidraRefs, TaskMonitor monitor)
			throws TriageEngine.NotGoBinaryException {
		ProgramMemoryReader mem = new ProgramMemoryReader(program);
		Progress p = progress(monitor);
		List<RefCollector> extra = new ArrayList<>();
		GhidraRefCollector grc = null;
		if (useGhidraRefs && program.getReferenceManager().getReferenceSourceIterator(
			program.getMinAddress(), true).hasNext()) {
			grc = new GhidraRefCollector(program);
			extra.add(grc);
		}
		TriageResult r = TriageEngine.run(mem, kb, extra, true, program.getName(), p);
		TriageSession s = new TriageSession(program, mem, r, kb);
		s.ghidraRefs = grc == null ? 0 : grc.refsSeen();
		s.loadOverrides();
		s.analyzeBoundaries();
		return s;
	}

	/**
	 * A session without a Ghidra program (CLI / test harness): browsing works, markup and
	 * override persistence do not.
	 */
	public static TriageSession detached(TriageResult r, KnowledgeBase kb) {
		return new TriageSession(null, null, r, kb);
	}

	static Progress progress(TaskMonitor monitor) {
		return new Progress() {
			String last;

			@Override
			public void update(String message, long current, long max) {
				if (!message.equals(last)) {
					monitor.setMessage(message);
					last = message;
				}
				monitor.setMaximum(Math.max(1, max));
				monitor.setProgress(current);
			}

			@Override
			public boolean isCancelled() {
				return monitor.isCancelled();
			}
		};
	}

	public Address addr(long a) {
		return mem.addr(a);
	}

	public FuncInfo funcAt(Address a) {
		if (a == null) {
			return null;
		}
		int i = result.funcContaining(a.getOffset());
		return i < 0 ? null : result.funcs.get(i);
	}

	// ------------------------------------------------------------------ boundaries

	public void analyzeBoundaries() {
		chunks.clear();
		missingFunctions = 0;
		FunctionIterator it = program.getFunctionManager().getFunctions(true);
		while (it.hasNext()) {
			Function f = it.next();
			long e = f.getEntryPoint().getOffset();
			if (result.funcAtEntry(e) >= 0) {
				continue;
			}
			if (result.funcContaining(e) >= 0) {
				chunks.add(f);
			}
		}
		for (FuncInfo f : result.funcs) {
			if (program.getFunctionManager().getFunctionAt(addr(f.fn.entry())) == null) {
				missingFunctions++;
			}
		}
	}

	// ------------------------------------------------------------------ overrides

	private void loadOverrides() {
		Options o = program.getOptions(OPTIONS);
		String s = o.getString(OVERRIDES_KEY, "");
		if (s == null || s.isEmpty()) {
			return;
		}
		for (String part : s.split(";")) {
			int eq = part.indexOf('=');
			if (eq < 0) {
				continue;
			}
			try {
				long a = Long.parseUnsignedLong(part.substring(0, eq), 16);
				int i = result.funcAtEntry(a);
				if (i >= 0) {
					result.funcs.get(i).override = part.substring(eq + 1).equals("1");
				}
			}
			catch (NumberFormatException e) {
				// ignore malformed entry
			}
		}
	}

	/** Persists the override set into the program options (undoable). */
	public void saveOverrides() {
		if (program == null) {
			return;
		}
		StringBuilder sb = new StringBuilder();
		for (FuncInfo f : result.funcs) {
			if (f.override != null) {
				if (sb.length() > 0) {
					sb.append(';');
				}
				sb.append(Long.toHexString(f.fn.entry())).append('=').append(f.override ? "1" : "0");
			}
		}
		int tx = program.startTransaction("GoTriage: save overrides");
		boolean ok = false;
		try {
			program.getOptions(OPTIONS).setString(OVERRIDES_KEY, sb.toString());
			ok = true;
		}
		finally {
			program.endTransaction(tx, ok);
		}
	}
}
