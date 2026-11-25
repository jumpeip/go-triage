package gotriage.core;

import java.util.ArrayList;
import java.util.List;

/** Runs the full pipeline: locate/parse Go metadata, collect references, classify and score. */
public final class TriageEngine {

	/** Thrown when no pclntab can be found. */
	public static final class NotGoBinaryException extends Exception {
		public NotGoBinaryException(String msg) {
			super(msg);
		}
	}

	private TriageEngine() {
	}

	/**
	 * @param mr image to analyse
	 * @param kb knowledge base
	 * @param extraCollectors additional reference collectors (e.g. Ghidra references); the byte
	 *            scanner always runs when the architecture is supported
	 * @param useByteScanner run the built-in byte scanner
	 */
	public static TriageResult run(MemoryReader mr, KnowledgeBase kb, List<RefCollector> extraCollectors,
			boolean useByteScanner, String binaryName, Progress p) throws NotGoBinaryException {
		if (p == null) {
			p = Progress.NONE;
		}
		TriageResult r = new TriageResult();
		r.binaryName = binaryName == null ? "" : binaryName;
		r.format = mr.format();
		r.arch = mr.arch();
		Mem m = new Mem(mr);

		p.update("Locating pclntab", 0, 1);
		r.pcln = PclnTable.locate(m);
		if (r.pcln == null) {
			throw new NotGoBinaryException("No Go pclntab found - not a Go binary, or the table is encrypted/stripped");
		}
		m.setPtrSize(r.pcln.ptrSize);

		p.update("Reading build info", 0, 1);
		r.buildInfo = GoBuildInfo.locate(m);
		m.setPtrSize(r.pcln.ptrSize);

		p.update("Locating moduledata", 0, 1);
		r.moduledata = ModuleData.locate(m, r.pcln);
		if (r.moduledata == null) {
			r.warnings.add("runtime.firstmoduledata not found: text base and type section are guessed");
		}
		Long mdText = r.moduledata == null ? null : r.moduledata.text;
		r.textStart = r.pcln.resolveTextStart(mr, mdText);

		List<GoFunc> funcs = r.pcln.readFunctions(m, r.textStart, p);
		int exec = 0;
		for (GoFunc f : funcs) {
			if (mr.isExecutable(f.entry())) {
				exec++;
			}
		}
		if (!funcs.isEmpty() && exec * 10 < funcs.size() * 9) {
			r.warnings.add(String.format("Only %d of %d pclntab entries fall in executable memory (text base %s)",
				exec, funcs.size(), Bytes.hex(r.textStart)));
		}
		for (GoFunc f : funcs) {
			r.funcs.add(new FuncInfo(r.funcs.size(), f, GoSymbol.parse(f.name())));
		}
		r.indexFunctions();

		int minor = r.buildInfo != null ? r.buildInfo.goMinor() : -1;
		r.types = new GoTypes(m, r.moduledata, minor, r.pcln.version);
		markWrapperFuncIds(r);

		List<RefCollector> collectors = new ArrayList<>();
		ByteScanner bs = new ByteScanner(m, mr.arch());
		if (useByteScanner && bs.supported()) {
			collectors.add(bs);
		}
		if (extraCollectors != null) {
			collectors.addAll(extraCollectors);
		}
		List<String> names = new ArrayList<>();
		for (RefCollector c : collectors) {
			if (p.isCancelled()) {
				break;
			}
			c.collect(r, p);
			names.add(c.name());
		}
		r.refSource = names.isEmpty() ? "none (unsupported architecture: run Ghidra auto-analysis)" : String.join(" + ", names);

		if (r.moduledata != null) {
			p.update("Calibrating type descriptors", 0, 1);
			r.types.calibrate(r.rawDataRefs, mr, r.pcln.version == PclnTable.Version.V12 ? 14 : 24);
			if (r.types.available()) {
				r.types.loadTypelinks(p);
				if (r.moduledata.ntypelinks < 8) {
					r.notes.add("typelinks table absent/empty: types are recovered from code references only");
				}
			}
			else {
				r.notes.add("type section could not be calibrated: type recovery disabled");
			}
		}

		Classifier.classify(r, kb, m, p);
		return r;
	}

	/**
	 * The runtime marks every compiler-generated function (method wrappers, eq/hash routines)
	 * with the last funcID value ("wrapper"); its numeric value varies by release, but it is by
	 * far the most frequent non-zero funcID, while the other special IDs occur once each.
	 */
	private static void markWrapperFuncIds(TriageResult r) {
		java.util.Map<Integer, Integer> counts = new java.util.HashMap<>();
		for (FuncInfo f : r.funcs) {
			if (f.fn.funcId() != 0) {
				counts.merge(f.fn.funcId(), 1, Integer::sum);
			}
		}
		int wrapperId = -1, best = 0;
		for (java.util.Map.Entry<Integer, Integer> e : counts.entrySet()) {
			if (e.getValue() > best) {
				best = e.getValue();
				wrapperId = e.getKey();
			}
		}
		if (best < 8) {
			wrapperId = -1;
		}
		for (FuncInfo f : r.funcs) {
			int id = f.fn.funcId();
			if (id == 0) {
				continue;
			}
			f.tags.add(id == wrapperId ? "wrapper-funcid" : "runtime-special");
		}
	}
}
