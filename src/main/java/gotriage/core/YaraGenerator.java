package gotriage.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Drafts a YARA rule from actor-specific artefacts. Go function names in the pclntab survive
 * stripping and are unique to the author's code, so they make good anchors alongside indicator
 * strings, the module path and build paths. The output is a starting point for the analyst.
 */
public final class YaraGenerator {

	private YaraGenerator() {
	}

	public static String generate(TriageResult r, String ruleName) {
		String name = sanitize(ruleName == null || ruleName.isBlank() ? "go_" + r.binaryName : ruleName);
		Set<String> fnNames = new LinkedHashSet<>();
		List<FuncInfo> fs = new ArrayList<>(r.actorFunctions());
		fs.sort(Comparator.comparing((FuncInfo f) -> -f.risk).thenComparing(f -> -f.fn.size()));
		for (FuncInfo f : fs) {
			String n = f.name();
			if (f.category == Category.GENERATED || f.sym.isClosure() || n.equals("main.main")
					|| n.equals("main.init") || n.length() < 10 || n.contains("[") || n.length() > 100) {
				continue;
			}
			fnNames.add(n);
			if (fnNames.size() >= 10) {
				break;
			}
		}
		Set<String> strs = new LinkedHashSet<>();
		List<StringInfo> ss = new ArrayList<>(r.strings.values());
		ss.sort(Comparator.comparing((StringInfo s) -> -s.weight).thenComparing(s -> -s.value.length()));
		for (StringInfo si : ss) {
			if (!si.exactLength || !si.referencedByActor(r)) {
				continue;
			}
			String v = si.value.strip();
			if (v.length() < 8 || v.length() > 120 || !hasSignal(v) || v.indexOf('\n') >= 0) {
				continue;
			}
			if (si.tags.isEmpty() && si.weight == 0 && strs.size() >= 6) {
				continue;
			}
			strs.add(si.value);
			if (strs.size() >= 12) {
				break;
			}
		}
		Set<String> meta = new LinkedHashSet<>();
		if (r.buildInfo != null && r.buildInfo.mainModulePath() != null
				&& !r.buildInfo.mainModulePath().equals("command-line-arguments")) {
			meta.add(r.buildInfo.mainModulePath());
		}
		for (String bp : r.buildPaths) {
			if (meta.size() >= 3) {
				break;
			}
			meta.add(bp);
		}

		StringBuilder sb = new StringBuilder();
		sb.append("rule ").append(name).append("\n{\n");
		sb.append("    meta:\n");
		sb.append("        description = \"Go binary - actor-specific artefacts recovered by go-triage (review before use)\"\n");
		sb.append("        go_version = \"").append(esc(r.goVersion())).append("\"\n");
		if (r.buildInfo != null && r.buildInfo.mainModulePath() != null) {
			sb.append("        go_module = \"").append(esc(r.buildInfo.mainModulePath())).append("\"\n");
		}
		sb.append("        generator = \"go-triage\"\n");
		sb.append("    strings:\n");
		sb.append("        $go1 = \"\\xff Go buildinf:\" ascii\n");
		sb.append("        $go2 = \"runtime.gopanic\" ascii\n");
		int i = 0;
		for (String fn : fnNames) {
			sb.append("        $fn").append(i++).append(" = \"").append(esc(fn)).append("\" ascii\n");
		}
		i = 0;
		for (String s : strs) {
			sb.append("        $s").append(i++).append(" = \"").append(esc(s)).append("\" ascii\n");
		}
		i = 0;
		for (String s : meta) {
			sb.append("        $m").append(i++).append(" = \"").append(esc(s)).append("\" ascii\n");
		}
		sb.append("    condition:\n");
		sb.append("        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE)\n");
		sb.append("        and any of ($go*)\n");
		List<String> parts = new ArrayList<>();
		if (!fnNames.isEmpty()) {
			parts.add(Math.min(3, fnNames.size()) + " of ($fn*)");
		}
		if (!strs.isEmpty()) {
			parts.add(Math.min(3, strs.size()) + " of ($s*)");
		}
		if (!meta.isEmpty()) {
			parts.add("any of ($m*)");
		}
		if (!parts.isEmpty()) {
			sb.append("        and (").append(String.join(" or ", parts)).append(")\n");
		}
		sb.append("}\n");
		return sb.toString();
	}

	private static boolean hasSignal(String v) {
		int alpha = 0;
		for (char c : v.toCharArray()) {
			if (Character.isLetterOrDigit(c)) {
				alpha++;
			}
		}
		return alpha * 2 >= v.length();
	}

	static String esc(String s) {
		StringBuilder b = new StringBuilder();
		for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
			int c = x & 0xff;
			if (c == '"' || c == '\\') {
				b.append('\\').append((char) c);
			}
			else if (c >= 0x20 && c < 0x7f) {
				b.append((char) c);
			}
			else {
				b.append(String.format("\\x%02x", c));
			}
		}
		return b.toString();
	}

	static String sanitize(String n) {
		String s = n.replaceAll("[^A-Za-z0-9_]", "_");
		if (s.isEmpty() || Character.isDigit(s.charAt(0))) {
			s = "r_" + s;
		}
		return s.length() > 120 ? s.substring(0, 120) : s;
	}
}
