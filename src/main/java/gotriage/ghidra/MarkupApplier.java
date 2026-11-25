package gotriage.ghidra;

import java.awt.Color;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import gotriage.core.Category;
import gotriage.core.FuncInfo;
import gotriage.core.StringInfo;
import gotriage.core.TriageResult;

/** Writes the triage results into the program: functions, names, namespaces, tags, bookmarks, colours, comments. */
public final class MarkupApplier {

	public static final String BOOKMARK_CATEGORY = "GoTriage";
	public static final String COMMENT_PREFIX = "GoTriage:";
	public static final String TAG_PREFIX = "GO_";
	public static final String NS_ROOT = "GoTriage";

	public enum NamespaceMode {
		CATEGORY_TREE("GoTriage::<Category>::<package path tree>"),
		PACKAGE_TREE("<package path tree> (split on '/')"),
		PACKAGE_FLAT("one namespace per package"),
		NONE("don't touch namespaces (full Go name as the function name)");

		public final String label;

		NamespaceMode(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	/** What to apply. */
	public static final class Options {
		public boolean createFunctions = true;
		public boolean fixChunks = true;
		public boolean rename = true;
		public NamespaceMode namespaces = NamespaceMode.CATEGORY_TREE;
		public boolean namespacesActorOnly = false;
		public boolean tags = true;
		public boolean bookmarks = true;
		public int bookmarkRiskThreshold = 30;
		public boolean colors = true;
		public boolean comments = true;
		public boolean defineStrings = true;
	}

	public static final Color COLOR_ACTOR = new Color(0xC8, 0xEC, 0xC8);
	public static final Color COLOR_ACTOR_MED = new Color(0xFF, 0xE4, 0xB0);
	public static final Color COLOR_ACTOR_HIGH = new Color(0xFF, 0xC4, 0xC4);
	public static final Color COLOR_UNKNOWN = new Color(0xE0, 0xE6, 0xFF);

	private final TriageSession s;
	private final Program program;
	private final Options o;
	private final ColorizingService colorizer;
	private final List<String> log = new ArrayList<>();

	public MarkupApplier(TriageSession s, Options o, ColorizingService colorizer) {
		this.s = s;
		this.program = s.program;
		this.o = o;
		this.colorizer = colorizer;
	}

	public List<String> log() {
		return log;
	}

	public void apply(TaskMonitor monitor) throws CancelledException {
		TriageResult r = s.result;
		int tx = program.startTransaction("GoTriage: apply markup");
		boolean ok = false;
		try {
			if (o.createFunctions) {
				createFunctions(monitor);
			}
			if (o.fixChunks) {
				fixChunks(monitor);
			}
			if (o.rename || o.namespaces != NamespaceMode.NONE) {
				names(monitor);
			}
			if (o.tags) {
				tags(monitor);
			}
			if (o.comments) {
				comments(monitor);
			}
			if (o.bookmarks) {
				bookmarks(monitor);
			}
			if (o.defineStrings) {
				strings(monitor);
			}
			ok = true;
		}
		finally {
			program.endTransaction(tx, ok);
		}
		// the colorizer manages its own transaction
		if (o.colors && colorizer != null) {
			colors(monitor);
		}
		s.analyzeBoundaries();
		log.add(String.format("Done: %d functions, %d chunks remaining, %d pclntab functions without a Ghidra function",
			r.funcs.size(), s.chunks.size(), s.missingFunctions));
	}

	// ------------------------------------------------------------------ functions

	private void createFunctions(TaskMonitor monitor) throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		Listing listing = program.getListing();
		AddressSet starts = new AddressSet();
		List<FuncInfo> missing = new ArrayList<>();
		for (FuncInfo f : s.result.funcs) {
			if (f.fn.size() <= 0) {
				continue;
			}
			Address a = s.addr(f.fn.entry());
			if (!program.getMemory().getExecuteSet().contains(a)) {
				continue;
			}
			if (fm.getFunctionAt(a) == null) {
				missing.add(f);
				if (listing.getInstructionAt(a) == null) {
					starts.add(a);
				}
			}
		}
		if (missing.isEmpty()) {
			return;
		}
		if (!starts.isEmpty()) {
			monitor.setMessage("GoTriage: disassembling " + starts.getNumAddresses() + " pclntab entries");
			DisassembleCommand dc = new DisassembleCommand(starts, null, true);
			dc.applyTo(program, monitor);
		}
		monitor.initialize(missing.size(), "GoTriage: creating functions from pclntab");
		int created = 0;
		for (FuncInfo f : missing) {
			monitor.increment();
			Address a = s.addr(f.fn.entry());
			if (fm.getFunctionAt(a) != null) {
				continue;
			}
			AddressSet range = new AddressSet(a, s.addr(f.fn.end() - 1));
			AddressSetView body = CreateFunctionCmd.getFunctionBody(monitor, program, a);
			AddressSet b = body == null || body.isEmpty() ? range : new AddressSet(body).intersect(range);
			if (b.isEmpty() || !b.contains(a)) {
				b = new AddressSet(a, a);
			}
			// don't overlap existing functions
			java.util.Iterator<Function> ov = fm.getFunctionsOverlapping(b);
			List<Function> overlapping = new ArrayList<>();
			while (ov.hasNext()) {
				overlapping.add(ov.next());
			}
			for (Function other : overlapping) {
				b.delete(other.getBody());
			}
			if (!b.contains(a)) {
				continue;
			}
			try {
				fm.createFunction(ghidraName(f, NamespaceMode.NONE), a, b, SourceType.ANALYSIS);
				created++;
			}
			catch (Exception e) {
				// keep going; some entries (e.g. linker markers) aren't real code
			}
		}
		log.add("Created " + created + " functions from the pclntab");
	}

	/** Removes Ghidra-created fragments that start inside a pclntab function and re-grows the parent. */
	private void fixChunks(TaskMonitor monitor) throws CancelledException {
		s.analyzeBoundaries();
		FunctionManager fm = program.getFunctionManager();
		int removed = 0;
		List<Function> parents = new ArrayList<>();
		for (Function chunk : new ArrayList<>(s.chunks)) {
			monitor.checkCancelled();
			Symbol sym = chunk.getSymbol();
			if (sym.getSource() == SourceType.USER_DEFINED) {
				continue;
			}
			FuncInfo owner = s.funcAt(chunk.getEntryPoint());
			if (owner == null) {
				continue;
			}
			if (fm.removeFunction(chunk.getEntryPoint())) {
				removed++;
				Function parent = fm.getFunctionAt(s.addr(owner.fn.entry()));
				if (parent != null) {
					parents.add(parent);
				}
			}
		}
		for (Function p : parents) {
			CreateFunctionCmd.fixupFunctionBody(program, p, monitor);
		}
		if (removed > 0) {
			log.add("Merged " + removed + " function chunks back into their pclntab owners");
		}
	}

	// ------------------------------------------------------------------ names / namespaces

	private void names(TaskMonitor monitor) throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		Map<String, Namespace> nsCache = new HashMap<>();
		monitor.initialize(s.result.funcs.size(), "GoTriage: naming functions");
		int renamed = 0, failed = 0;
		for (FuncInfo f : s.result.funcs) {
			monitor.increment();
			Function fn = fm.getFunctionAt(s.addr(f.fn.entry()));
			if (fn == null) {
				continue;
			}
			Symbol sym = fn.getSymbol();
			if (sym.getSource() == SourceType.USER_DEFINED) {
				continue;
			}
			NamespaceMode mode = o.namespaces;
			if (o.namespacesActorOnly && !(f.isActor() || f.isActorGenerated())) {
				mode = NamespaceMode.NONE;
			}
			try {
				Namespace ns = namespaceFor(f, mode, nsCache);
				String name = o.rename ? ghidraName(f, mode) : sym.getName();
				if (!name.equals(sym.getName()) || !ns.equals(sym.getParentNamespace())) {
					sym.setNameAndNamespace(name, ns, SourceType.ANALYSIS);
					renamed++;
				}
			}
			catch (Exception e) {
				failed++;
			}
		}
		log.add("Named/namespaced " + renamed + " functions" + (failed > 0 ? " (" + failed + " failed)" : ""));
	}

	static String ghidraName(FuncInfo f, NamespaceMode mode) {
		String n = mode == NamespaceMode.NONE || f.sym.packagePath.isEmpty() ? f.name() : f.sym.shortName();
		if (n.isEmpty()) {
			n = f.name();
		}
		return SymbolUtilities.replaceInvalidChars(n, true);
	}

	private Namespace namespaceFor(FuncInfo f, NamespaceMode mode, Map<String, Namespace> cache) throws Exception {
		Namespace global = program.getGlobalNamespace();
		if (mode == NamespaceMode.NONE) {
			return global;
		}
		String pkg = f.sym.packagePath;
		List<String> parts = new ArrayList<>();
		if (mode == NamespaceMode.CATEGORY_TREE) {
			parts.add(NS_ROOT);
			Category c = f.category == Category.GENERATED ? Category.GENERATED
					: f.override != null ? (f.override ? Category.ACTOR : (f.category.isActorLike() ? Category.UNKNOWN : f.category))
					: f.category;
			parts.add(c.label.replace('-', '_'));
		}
		if (pkg.isEmpty()) {
			parts.add(f.category == Category.GENERATED ? "_compiler" : "_native");
		}
		else if (mode == NamespaceMode.PACKAGE_FLAT) {
			parts.add(clean(pkg));
		}
		else {
			for (String e : pkg.split("/")) {
				if (!e.isEmpty()) {
					parts.add(clean(e));
				}
			}
		}
		String path = String.join(Namespace.DELIMITER, parts);
		Namespace ns = cache.get(path);
		if (ns == null) {
			ns = NamespaceUtils.createNamespaceHierarchy(path, global, program, SourceType.ANALYSIS);
			cache.put(path, ns);
		}
		return ns;
	}

	private static String clean(String e) {
		return SymbolUtilities.replaceInvalidChars(e.replace("::", "__"), true);
	}

	// ------------------------------------------------------------------ tags / comments / bookmarks

	private void tags(TaskMonitor monitor) throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		monitor.initialize(s.result.funcs.size(), "GoTriage: tagging functions");
		for (FuncInfo f : s.result.funcs) {
			monitor.increment();
			Function fn = fm.getFunctionAt(s.addr(f.fn.entry()));
			if (fn == null) {
				continue;
			}
			removeOurTags(fn);
			fn.addTag(TAG_PREFIX + (f.isActor() ? "ACTOR" : f.category.name()));
			if (f.isActor() || f.isActorGenerated()) {
				for (String cap : f.caps.keySet()) {
					fn.addTag(TAG_PREFIX + "CAP_" + cap);
				}
				if (f.risk >= o.bookmarkRiskThreshold) {
					fn.addTag(TAG_PREFIX + "SUSPICIOUS");
				}
			}
		}
	}

	private static void removeOurTags(Function fn) {
		for (FunctionTag t : new ArrayList<>(fn.getTags())) {
			if (t.getName().startsWith(TAG_PREFIX)) {
				fn.removeTag(t.getName());
			}
		}
	}

	private void comments(TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		monitor.initialize(s.result.funcs.size(), "GoTriage: plate comments");
		for (FuncInfo f : s.result.funcs) {
			monitor.increment();
			if (!(f.isActor() || f.risk > 0 && f.category == Category.THIRD_PARTY && f.risk >= o.bookmarkRiskThreshold)) {
				continue;
			}
			Address a = s.addr(f.fn.entry());
			String existing = listing.getComment(CommentType.PLATE, a);
			if (existing != null && !existing.isBlank() && !existing.startsWith(COMMENT_PREFIX)) {
				continue; // never overwrite an analyst's comment
			}
			listing.setComment(a, CommentType.PLATE, plate(f));
		}
	}

	static String plate(FuncInfo f) {
		StringBuilder sb = new StringBuilder();
		sb.append(COMMENT_PREFIX).append(' ').append(f.isActor() ? "LIKELY ACTOR CODE" : f.category.label)
				.append(" | confidence ").append(f.actorConfidence).append(" | risk ").append(f.risk).append('\n');
		sb.append(f.name()).append('\n');
		if (!f.sourceLocation().isEmpty()) {
			sb.append("source: ").append(f.sourceLocation()).append('\n');
		}
		for (String w : f.attributionReasons) {
			sb.append("why: ").append(w).append('\n');
		}
		int n = 0;
		for (String w : f.riskReasons) {
			if (n++ >= 12) {
				sb.append("... (").append(f.riskReasons.size() - 12).append(" more in the Go Triage window)\n");
				break;
			}
			sb.append("risk: ").append(w).append('\n');
		}
		if (!f.tags.isEmpty()) {
			sb.append("tags: ").append(String.join(", ", f.tags)).append('\n');
		}
		return sb.toString().stripTrailing();
	}

	private void bookmarks(TaskMonitor monitor) throws CancelledException {
		BookmarkManager bm = program.getBookmarkManager();
		clearBookmarks(bm, monitor);
		int n = 0;
		for (FuncInfo f : s.result.funcs) {
			monitor.checkCancelled();
			if (!f.isActor()) {
				continue;
			}
			Address a = s.addr(f.fn.entry());
			String caps = String.join(",", f.allCaps());
			String text = "Actor [conf " + f.actorConfidence + ", risk " + f.risk + "] " + f.name()
					+ (caps.isEmpty() ? "" : " :: " + caps);
			bm.setBookmark(a, f.risk >= o.bookmarkRiskThreshold ? BookmarkType.WARNING : BookmarkType.NOTE,
				BOOKMARK_CATEGORY, text);
			n++;
		}
		for (StringInfo si : s.result.strings.values()) {
			if (!si.tags.isEmpty() && si.referencedByActor(s.result)) {
				bm.setBookmark(s.addr(si.address), BookmarkType.INFO, BOOKMARK_CATEGORY,
					"IOC [" + String.join(",", si.tags) + "] " + clip(si.value));
				n++;
			}
		}
		log.add("Added " + n + " bookmarks (category '" + BOOKMARK_CATEGORY + "')");
	}

	private static void clearBookmarks(BookmarkManager bm, TaskMonitor monitor) throws CancelledException {
		for (String t : new String[] { BookmarkType.NOTE, BookmarkType.WARNING, BookmarkType.INFO,
			BookmarkType.ANALYSIS }) {
			bm.removeBookmarks(t, BOOKMARK_CATEGORY, monitor);
		}
	}

	private static String clip(String v) {
		String t = v.replace("\n", "\\n").replace("\r", "\\r");
		return t.length() > 120 ? t.substring(0, 117) + "..." : t;
	}

	private void strings(TaskMonitor monitor) throws CancelledException {
		int n = 0;
		for (StringInfo si : s.result.strings.values()) {
			monitor.checkCancelled();
			if (!si.exactLength || !si.referencedByActor(s.result)) {
				continue;
			}
			int len = si.value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
			try {
				DataUtilities.createData(program, s.addr(si.address), new StringUTF8DataType(), len,
					DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				n++;
			}
			catch (Exception e) {
				// conflicting defined data: leave it alone
			}
		}
		log.add("Defined " + n + " Go string literals referenced by actor code");
	}

	// ------------------------------------------------------------------ colours

	private void colors(TaskMonitor monitor) {
		Map<Color, AddressSet> sets = new LinkedHashMap<>();
		FunctionManager fm = program.getFunctionManager();
		for (FuncInfo f : s.result.funcs) {
			if (!f.isActor()) {
				continue;
			}
			Color c = f.risk >= 60 ? COLOR_ACTOR_HIGH
					: f.risk >= o.bookmarkRiskThreshold ? COLOR_ACTOR_MED
					: f.category == Category.UNKNOWN ? COLOR_UNKNOWN : COLOR_ACTOR;
			Function fn = fm.getFunctionAt(s.addr(f.fn.entry()));
			AddressSetView body = fn != null ? fn.getBody()
					: new AddressSet(s.addr(f.fn.entry()), s.addr(Math.max(f.fn.entry(), f.fn.end() - 1)));
			sets.computeIfAbsent(c, k -> new AddressSet()).add(body);
		}
		int tx = program.startTransaction("GoTriage: colours");
		boolean ok = false;
		try {
			clearColors(s, colorizer);
			for (Map.Entry<Color, AddressSet> e : sets.entrySet()) {
				colorizer.setBackgroundColor(e.getValue(), e.getKey());
			}
			ok = true;
		}
		catch (RuntimeException e) {
			Msg.warn(this, "GoTriage: colouring failed: " + e.getMessage());
		}
		finally {
			program.endTransaction(tx, ok);
		}
		log.add("Coloured " + sets.values().stream().mapToLong(AddressSet::getNumAddresses).sum()
			+ " bytes of actor code");
	}

	private static void clearColors(TriageSession s, ColorizingService colorizer) {
		for (Color c : new Color[] { COLOR_ACTOR, COLOR_ACTOR_MED, COLOR_ACTOR_HIGH, COLOR_UNKNOWN }) {
			AddressSetView v = colorizer.getBackgroundColorAddresses(c);
			if (v != null && !v.isEmpty()) {
				colorizer.clearBackgroundColor(v);
			}
		}
	}

	// ------------------------------------------------------------------ clear

	/** Removes GoTriage bookmarks, tags, plate comments and colours (names/namespaces are kept). */
	public static void clear(TriageSession s, ColorizingService colorizer, TaskMonitor monitor) throws CancelledException {
		Program program = s.program;
		int tx = program.startTransaction("GoTriage: clear markup");
		boolean ok = false;
		try {
			clearBookmarks(program.getBookmarkManager(), monitor);
			Listing listing = program.getListing();
			FunctionManager fm = program.getFunctionManager();
			for (FuncInfo f : s.result.funcs) {
				monitor.checkCancelled();
				Address a = s.addr(f.fn.entry());
				String c = listing.getComment(CommentType.PLATE, a);
				if (c != null && c.startsWith(COMMENT_PREFIX)) {
					listing.setComment(a, CommentType.PLATE, null);
				}
				Function fn = fm.getFunctionAt(a);
				if (fn != null) {
					removeOurTags(fn);
				}
			}
			if (colorizer != null) {
				clearColors(s, colorizer);
			}
			ok = true;
		}
		finally {
			program.endTransaction(tx, ok);
		}
	}
}
