package gotriage.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Everything recovered from one Go binary. */
public final class TriageResult {

	/** A raw reference collected by a {@link RefCollector}, resolved by the engine. */
	public record DataRef(int from, long target, int length) {
	}

	public String binaryName = "";
	public String format = "";
	public String arch = "";
	public PclnTable pcln;
	public ModuleData moduledata;
	public GoBuildInfo buildInfo;
	public GoTypes types;
	public long textStart;

	public final List<FuncInfo> funcs = new ArrayList<>();
	public final Map<String, PackageInfo> packages = new TreeMap<>();
	public final Map<Long, StringInfo> strings = new LinkedHashMap<>();
	public final List<DataRef> rawDataRefs = new ArrayList<>();

	/** Detected GOROOT prefix of source paths ("" when -trimpath, null when unknown). */
	public String goroot;
	public final Set<String> buildPaths = new LinkedHashSet<>();
	public final Set<String> buildUsers = new LinkedHashSet<>();
	public boolean trimpath;
	public boolean garbleSuspected;
	public String garbleEvidence = "";
	public final List<String> notes = new ArrayList<>();
	public final List<String> warnings = new ArrayList<>();
	public final Map<Category, Integer> categoryCounts = new EnumMap<>(Category.class);
	public final Map<Category, Long> categoryBytes = new EnumMap<>(Category.class);
	public String refSource = "";

	private long[] sortedEntries;
	private int[] sortedIndex;
	private final Map<Long, Integer> byEntry = new HashMap<>();

	/** Must be called after {@link #funcs} is populated. */
	public void indexFunctions() {
		byEntry.clear();
		int n = funcs.size();
		Integer[] order = new Integer[n];
		for (int i = 0; i < n; i++) {
			order[i] = i;
			byEntry.putIfAbsent(funcs.get(i).fn.entry(), i);
		}
		Arrays.sort(order, (a, b) -> Long.compareUnsigned(funcs.get(a).fn.entry(), funcs.get(b).fn.entry()));
		sortedEntries = new long[n];
		sortedIndex = new int[n];
		for (int i = 0; i < n; i++) {
			sortedIndex[i] = order[i];
			sortedEntries[i] = funcs.get(order[i]).fn.entry();
		}
	}

	/** Function whose entry is exactly {@code addr}, or -1. */
	public int funcAtEntry(long addr) {
		Integer i = byEntry.get(addr);
		return i == null ? -1 : i;
	}

	/** Function whose [entry, end) contains {@code addr}, or -1. */
	public int funcContaining(long addr) {
		if (sortedEntries == null || sortedEntries.length == 0) {
			return -1;
		}
		int lo = 0, hi = sortedEntries.length - 1, best = -1;
		while (lo <= hi) {
			int mid = (lo + hi) >>> 1;
			if (Long.compareUnsigned(sortedEntries[mid], addr) <= 0) {
				best = mid;
				lo = mid + 1;
			}
			else {
				hi = mid - 1;
			}
		}
		if (best < 0) {
			return -1;
		}
		FuncInfo f = funcs.get(sortedIndex[best]);
		return Long.compareUnsigned(addr, f.fn.end()) < 0 ? f.index : -1;
	}

	public FuncInfo byName(String name) {
		for (FuncInfo f : funcs) {
			if (f.name().equals(name)) {
				return f;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------ edges

	public void addCall(int from, int to) {
		if (from < 0 || to < 0 || from == to) {
			return;
		}
		funcs.get(from).callees.add(to);
		funcs.get(to).callers.add(from);
	}

	public void addFuncRef(int from, int to) {
		if (from < 0 || to < 0 || from == to) {
			return;
		}
		funcs.get(from).funcRefs.add(to);
		funcs.get(from).callees.add(to);
		funcs.get(to).callers.add(from);
	}

	public void addDataRef(int from, long target, int length) {
		rawDataRefs.add(new DataRef(from, target, length));
	}

	// ------------------------------------------------------------------ queries

	public List<FuncInfo> actorFunctions() {
		List<FuncInfo> out = new ArrayList<>();
		for (FuncInfo f : funcs) {
			if (f.isActor()) {
				out.add(f);
			}
		}
		return out;
	}

	public List<FuncInfo> entryPoints() {
		List<FuncInfo> out = new ArrayList<>();
		for (FuncInfo f : funcs) {
			if (f.tags.contains("entry-point") || (f.isActor() && f.tags.contains("init"))) {
				out.add(f);
			}
		}
		return out;
	}

	public String goVersion() {
		if (buildInfo != null && buildInfo.goVersion != null) {
			return buildInfo.goVersion;
		}
		return pcln != null ? pcln.version.label : "?";
	}
}
