package gotriage.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** JSON / CSV / Markdown exports of a {@link TriageResult}. */
public final class Reports {

	private Reports() {
	}

	/** Functions sorted for triage: actor first, then by risk, then by address. */
	public static List<FuncInfo> triageOrder(TriageResult r) {
		List<FuncInfo> l = new ArrayList<>(r.funcs);
		l.sort(Comparator.comparing((FuncInfo f) -> !f.isActor())
				.thenComparing(f -> -f.risk)
				.thenComparing(f -> f.fn.entry()));
		return l;
	}

	// ------------------------------------------------------------------ JSON

	public static String json(TriageResult r, boolean actorOnly) {
		Json j = new Json();
		j.beginObject();
		j.kv("tool", "go-triage");
		j.kv("binary", r.binaryName);
		j.kv("format", r.format);
		j.kv("arch", r.arch);
		j.kv("goVersion", r.goVersion());
		j.kv("pclntab", r.pcln.toString());
		j.kv("referenceSource", r.refSource);
		j.kv("goroot", r.goroot);
		j.kv("trimpath", r.trimpath);
		j.kv("garbleSuspected", r.garbleSuspected);
		j.kv("garbleEvidence", r.garbleEvidence);
		j.kv("buildPaths", r.buildPaths);
		j.kv("buildUsers", r.buildUsers);
		j.kv("notes", r.notes);
		j.kv("warnings", r.warnings);
		if (r.buildInfo != null) {
			GoBuildInfo bi = r.buildInfo;
			j.name("buildInfo").beginObject();
			j.kv("goVersion", bi.goVersion);
			j.kv("path", bi.mainPackagePath);
			j.kv("mainModule", bi.mainModule == null ? null : bi.mainModule.path());
			j.kv("mainModuleVersion", bi.mainModule == null ? null : bi.mainModule.version());
			j.kv("settings", bi.settings);
			j.name("deps").beginArray();
			for (GoBuildInfo.Module d : bi.deps) {
				j.beginObject().kv("path", d.path()).kv("version", d.version()).kv("sum", d.sum())
						.kv("replacedBy", d.replacedBy()).endObject();
			}
			j.endArray();
			j.endObject();
		}
		j.name("categoryCounts").beginObject();
		for (Map.Entry<Category, Integer> e : r.categoryCounts.entrySet()) {
			j.kv(e.getKey().name(), e.getValue());
		}
		j.endObject();
		j.name("packages").beginArray();
		for (PackageInfo pi : r.packages.values()) {
			if (actorOnly && !pi.category.isActorLike()) {
				continue;
			}
			j.beginObject().kv("path", pi.path).kv("category", pi.category.name()).kv("confidence", pi.confidence)
					.kv("functions", pi.funcs.size()).kv("actorFunctions", pi.actorFuncs).kv("maxRisk", pi.maxRisk)
					.kv("module", pi.moduleLabel()).kv("capabilities", pi.caps).kv("reasons", pi.reasons).endObject();
		}
		j.endArray();
		j.name("functions").beginArray();
		for (FuncInfo f : triageOrder(r)) {
			if (actorOnly && !f.isActor()) {
				continue;
			}
			j.beginObject();
			j.kv("address", Bytes.hex(f.fn.entry()));
			j.kv("size", f.fn.size());
			j.kv("name", f.name());
			j.kv("package", f.packagePath());
			j.kv("receiver", f.sym.receiver);
			j.kv("function", f.sym.shortName());
			j.kv("category", f.category.name());
			j.kv("actor", f.isActor());
			j.kv("confidence", f.actorConfidence);
			j.kv("risk", f.risk);
			j.kv("source", f.sourceLocation());
			j.kv("tags", f.tags);
			j.kv("capabilities", f.caps);
			j.kv("indirectCapabilities", f.transitiveCaps);
			j.kv("attribution", f.attributionReasons);
			j.kv("riskReasons", f.riskReasons);
			j.name("callees").beginArray();
			for (int c : f.callees) {
				j.v(r.funcs.get(c).name());
			}
			j.endArray();
			j.name("strings").beginArray();
			for (long s : f.strings) {
				StringInfo si = r.strings.get(s);
				if (si != null) {
					j.v(si.value);
				}
			}
			j.endArray();
			j.endObject();
		}
		j.endArray();
		j.name("strings").beginArray();
		for (StringInfo si : r.strings.values()) {
			if (actorOnly && !si.referencedByActor(r)) {
				continue;
			}
			if (si.tags.isEmpty() && !si.referencedByActor(r)) {
				continue;
			}
			j.beginObject().kv("address", Bytes.hex(si.address)).kv("value", si.value).kv("exact", si.exactLength)
					.kv("tags", si.tags).kv("capabilities", si.caps);
			j.name("referencedBy").beginArray();
			for (int i : si.referencedBy) {
				j.v(r.funcs.get(i).name());
			}
			j.endArray().endObject();
		}
		j.endArray();
		j.name("types").beginArray();
		if (r.types != null) {
			for (GoTypes.GoType t : r.types.all().values()) {
				j.beginObject().kv("address", Bytes.hex(t.address)).kv("name", t.name).kv("kind", t.kindName())
						.kv("fields", t.fields).endObject();
			}
		}
		j.endArray();
		j.endObject();
		return j.toString();
	}

	// ------------------------------------------------------------------ CSV

	public static String csv(TriageResult r, boolean actorOnly) {
		StringBuilder sb = new StringBuilder();
		sb.append("address,category,actor,confidence,risk,package,function,receiver,capabilities,source,size,callers,callees,tags,reasons\n");
		for (FuncInfo f : triageOrder(r)) {
			if (actorOnly && !f.isActor()) {
				continue;
			}
			List<String> reasons = new ArrayList<>(f.attributionReasons);
			reasons.addAll(f.riskReasons);
			sb.append(Bytes.hex(f.fn.entry())).append(',')
					.append(f.category.name()).append(',')
					.append(f.isActor()).append(',')
					.append(f.actorConfidence).append(',')
					.append(f.risk).append(',')
					.append(q(f.packagePath())).append(',')
					.append(q(f.sym.shortName())).append(',')
					.append(q(f.sym.receiver == null ? "" : f.sym.receiver)).append(',')
					.append(q(String.join(" ", f.allCaps()))).append(',')
					.append(q(f.sourceLocation())).append(',')
					.append(f.fn.size()).append(',')
					.append(f.callers.size()).append(',')
					.append(f.callees.size()).append(',')
					.append(q(String.join(" ", f.tags))).append(',')
					.append(q(String.join(" | ", reasons))).append('\n');
		}
		return sb.toString();
	}

	private static String q(String s) {
		if (s == null) {
			return "";
		}
		if (s.indexOf(',') < 0 && s.indexOf('"') < 0 && s.indexOf('\n') < 0) {
			return s;
		}
		return '"' + s.replace("\"", "\"\"").replace("\n", " ") + '"';
	}

	// ------------------------------------------------------------------ Markdown

	public static String markdown(TriageResult r, int topN) {
		StringBuilder sb = new StringBuilder();
		sb.append("# Go triage: ").append(r.binaryName).append("\n\n");
		sb.append("| | |\n|---|---|\n");
		row(sb, "Go version", r.goVersion());
		row(sb, "Format / arch", r.format + " / " + r.arch);
		row(sb, "pclntab", r.pcln.toString());
		if (r.buildInfo != null) {
			GoBuildInfo bi = r.buildInfo;
			row(sb, "Main package", bi.mainPackagePath);
			row(sb, "Main module", bi.mainModule == null ? "" : bi.mainModule.path() + " " + nz(bi.mainModule.version()));
			for (String k : new String[] { "GOOS", "GOARCH", "CGO_ENABLED", "-ldflags", "-tags", "-trimpath",
				"-buildmode", "-compiler", "vcs", "vcs.revision", "vcs.time", "vcs.modified" }) {
				if (bi.settings.containsKey(k)) {
					row(sb, k, bi.settings.get(k));
				}
			}
			row(sb, "Dependencies", String.valueOf(bi.deps.size()));
		}
		else {
			row(sb, "Build info", "absent (stripped or pre-1.13)");
		}
		row(sb, "GOROOT (from paths)", r.goroot == null ? "?" : r.goroot.isEmpty() ? "(trimpath)" : r.goroot);
		row(sb, "Build users", String.join(", ", r.buildUsers));
		row(sb, "Obfuscation", r.garbleSuspected ? "garble suspected: " + r.garbleEvidence : "none detected");
		row(sb, "References from", r.refSource);
		sb.append("\n## Code composition\n\n| Category | Functions | Bytes |\n|---|---:|---:|\n");
		for (Category c : Category.values()) {
			sb.append("| ").append(c.label).append(" | ").append(r.categoryCounts.getOrDefault(c, 0)).append(" | ")
					.append(r.categoryBytes.getOrDefault(c, 0L)).append(" |\n");
		}
		if (!r.buildPaths.isEmpty()) {
			sb.append("\n## Build paths (actor source tree)\n\n");
			for (String p : r.buildPaths) {
				sb.append("- `").append(p).append("`\n");
			}
		}
		sb.append("\n## Actor packages\n\n| Package | Functions | Max risk | Capabilities | Why |\n|---|---:|---:|---|---|\n");
		for (PackageInfo pi : r.packages.values()) {
			if (!pi.category.isActorLike()) {
				continue;
			}
			sb.append("| `").append(pi.path).append("` | ").append(pi.funcs.size()).append(" | ").append(pi.maxRisk)
					.append(" | ").append(String.join(", ", pi.caps)).append(" | ")
					.append(String.join("; ", pi.reasons).replace("|", "\\|")).append(" |\n");
		}
		sb.append("\n## Notable libraries\n\n");
		boolean any = false;
		for (PackageInfo pi : r.packages.values()) {
			if (pi.library != null && pi.library.isNotable() && !pi.funcs.isEmpty()) {
				sb.append("- `").append(pi.path).append("` - ").append(pi.library.libClass()).append(": ")
						.append(pi.library.description()).append("\n");
				any = true;
			}
		}
		if (!any) {
			sb.append("(none)\n");
		}
		sb.append("\n## Top actor functions by risk\n\n");
		List<FuncInfo> fs = new ArrayList<>(r.actorFunctions());
		fs.sort(Comparator.comparing((FuncInfo f) -> -f.risk).thenComparing(f -> f.fn.entry()));
		int n = 0;
		for (FuncInfo f : fs) {
			if (n++ >= topN) {
				break;
			}
			sb.append("### `").append(f.name()).append("` @ ").append(Bytes.hex(f.fn.entry()))
					.append(" - risk ").append(f.risk).append(", confidence ").append(f.actorConfidence).append("\n\n");
			if (!f.sourceLocation().isEmpty()) {
				sb.append("Source: `").append(f.sourceLocation()).append("`\n\n");
			}
			for (String s : f.attributionReasons) {
				sb.append("- ").append(s).append("\n");
			}
			for (String s : f.riskReasons) {
				sb.append("- ").append(s).append("\n");
			}
			sb.append("\n");
		}
		sb.append("\n## Indicator strings (referenced by actor code)\n\n");
		for (StringInfo si : r.strings.values()) {
			if (!si.tags.isEmpty() && si.referencedByActor(r)) {
				sb.append("- `").append(Classifier.clip(si.value, 160).replace("`", "'")).append("` [")
						.append(String.join(", ", si.tags)).append("]\n");
			}
		}
		if (!r.warnings.isEmpty() || !r.notes.isEmpty()) {
			sb.append("\n## Notes\n\n");
			for (String w : r.warnings) {
				sb.append("- WARNING: ").append(w).append("\n");
			}
			for (String w : r.notes) {
				sb.append("- ").append(w).append("\n");
			}
		}
		return sb.toString();
	}

	private static void row(StringBuilder sb, String k, String v) {
		sb.append("| ").append(k).append(" | ").append(v == null ? "" : v.replace("|", "\\|")).append(" |\n");
	}

	private static String nz(String s) {
		return s == null ? "" : s;
	}
}
