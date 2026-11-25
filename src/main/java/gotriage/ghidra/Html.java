package gotriage.ghidra;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import gotriage.core.Bytes;
import gotriage.core.Category;
import gotriage.core.FuncInfo;
import gotriage.core.GoBuildInfo;
import gotriage.core.GoTypes;
import gotriage.core.PackageInfo;
import gotriage.core.StringInfo;
import gotriage.core.TriageResult;

/**
 * HTML for the overview and detail panes. Links use two schemes handled by the provider:
 * {@code fn:<index>} selects a function, {@code addr:<hex>} navigates the listing.
 */
final class Html {

	private Html() {
	}

	static String esc(String s) {
		if (s == null) {
			return "";
		}
		StringBuilder b = new StringBuilder(s.length() + 16);
		for (char c : s.toCharArray()) {
			switch (c) {
				case '<' -> b.append("&lt;");
				case '>' -> b.append("&gt;");
				case '&' -> b.append("&amp;");
				case '"' -> b.append("&quot;");
				case '\n' -> b.append("\\n");
				case '\r' -> b.append("\\r");
				case '\t' -> b.append("\\t");
				default -> b.append(c < 0x20 ? '.' : c);
			}
		}
		return b.toString();
	}

	static String clip(String s, int n) {
		return s.length() > n ? s.substring(0, n - 3) + "..." : s;
	}

	static String fnLink(FuncInfo f) {
		return "<a href=\"fn:" + f.index + "\">" + esc(f.name()) + "</a>";
	}

	static String addrLink(long a) {
		return "<a href=\"addr:" + Long.toHexString(a) + "\">0x" + Long.toHexString(a) + "</a>";
	}

	private static final String STYLE = "<style>body{font-family:sans-serif;font-size:11pt;margin:6px}"
			+ "h2{font-size:14pt;margin:4px 0}h3{font-size:12pt;margin:10px 0 2px 0}"
			+ "td{padding:1px 8px 1px 0;vertical-align:top}.k{font-weight:bold}"
			+ ".mono{font-family:monospaced}.dim{color:gray}.warn{color:#c05000}</style>";

	// ------------------------------------------------------------------ overview

	static String overview(TriageSession s) {
		TriageResult r = s.result;
		StringBuilder b = new StringBuilder("<html><head>" + STYLE + "</head><body>");
		b.append("<h2>").append(esc(r.binaryName)).append(" &mdash; ").append(esc(r.goVersion())).append("</h2>");
		b.append("<table>");
		row(b, "Format / arch", r.format + " / " + r.arch);
		row(b, "pclntab", r.pcln.toString());
		row(b, "Text base", Bytes.hex(r.textStart));
		if (r.moduledata != null) {
			row(b, "moduledata", Bytes.hex(r.moduledata.address) + (r.types != null && r.types.available()
					? "  (types " + Bytes.hex(r.moduledata.types) + ", " + r.types.all().size() + " decoded)"
					: ""));
		}
		GoBuildInfo bi = r.buildInfo;
		if (bi != null) {
			row(b, "Main package", bi.mainPackagePath);
			row(b, "Main module", bi.mainModule == null ? "" : bi.mainModule.path() + " " + nz(bi.mainModule.version()));
			for (String k : new String[] { "GOOS", "GOARCH", "CGO_ENABLED", "-ldflags", "-tags", "-trimpath",
				"-buildmode", "vcs.revision", "vcs.time", "vcs.modified" }) {
				if (bi.settings.containsKey(k)) {
					row(b, k, bi.settings.get(k));
				}
			}
			row(b, "Dependencies", bi.deps.size() + " modules (see the Build tab)");
		}
		else {
			rowHtml(b, "Build info", "<span class=warn>absent</span> (stripped, pre-Go 1.13, or obfuscated)");
		}
		row(b, "GOROOT", r.goroot == null ? "unknown" : r.goroot.isEmpty() ? "(trimpath)" : r.goroot);
		if (!r.buildUsers.isEmpty()) {
			row(b, "Build users", String.join(", ", r.buildUsers));
		}
		if (r.garbleSuspected) {
			rowHtml(b, "Obfuscation", "<span class=warn>garble suspected</span>: " + esc(r.garbleEvidence));
		}
		row(b, "References", r.refSource + (s.ghidraRefs > 0 ? " (" + s.ghidraRefs + " Ghidra refs)" : ""));
		row(b, "Ghidra functions", s.missingFunctions + " pclntab functions without a Ghidra function, "
				+ s.chunks.size() + " Ghidra fragments inside pclntab functions"
				+ (s.missingFunctions + s.chunks.size() > 0 ? "  -> use Apply Markup to fix" : ""));
		b.append("</table>");

		b.append("<h3>Code composition</h3><table>");
		long total = 0;
		for (long v : r.categoryBytes.values()) {
			total += v;
		}
		for (Category c : Category.values()) {
			int n = r.categoryCounts.getOrDefault(c, 0);
			long bytes = r.categoryBytes.getOrDefault(c, 0L);
			int pct = total == 0 ? 0 : (int) Math.round(100.0 * bytes / total);
			b.append("<tr><td class=k>").append(c.label).append("</td><td align=right>").append(n)
					.append(" fns</td><td align=right>").append(bytes / 1024).append(" KB</td><td>")
					.append(bar(pct)).append(" ").append(pct).append("%</td><td class=dim>").append(esc(c.description))
					.append("</td></tr>");
		}
		b.append("</table>");
		int actor = r.actorFunctions().size();
		b.append("<p><b>Focus set: ").append(actor).append(" likely-actor functions</b> out of ").append(r.funcs.size())
				.append(" &mdash; everything else is runtime, standard library, dependencies or compiler-generated code.</p>");

		List<FuncInfo> ep = r.entryPoints();
		if (!ep.isEmpty()) {
			b.append("<h3>Actor entry points</h3><ul>");
			for (FuncInfo f : ep) {
				b.append("<li>").append(fnLink(f)).append(" <span class=dim>").append(esc(String.join(", ", f.tags)))
						.append("</span></li>");
			}
			b.append("</ul>");
		}

		List<FuncInfo> fs = new ArrayList<>(r.actorFunctions());
		fs.sort(Comparator.comparing((FuncInfo f) -> -f.risk).thenComparing(f -> f.fn.entry()));
		b.append("<h3>Highest-risk actor functions</h3><table>");
		for (int i = 0; i < Math.min(15, fs.size()); i++) {
			FuncInfo f = fs.get(i);
			if (f.risk == 0) {
				break;
			}
			b.append("<tr><td align=right><b>").append(f.risk).append("</b></td><td>").append(fnLink(f))
					.append("</td><td class=dim>").append(esc(String.join(", ", f.allCaps()))).append("</td></tr>");
		}
		b.append("</table>");

		b.append("<h3>Notable libraries</h3><ul>");
		boolean any = false;
		for (PackageInfo pi : r.packages.values()) {
			if (pi.library != null && pi.library.isNotable()) {
				b.append("<li><b>").append(esc(pi.path)).append("</b> &mdash; ").append(esc(pi.library.libClass()))
						.append(": ").append(esc(pi.library.description())).append("</li>");
				any = true;
			}
		}
		if (!any) {
			b.append("<li class=dim>none</li>");
		}
		b.append("</ul>");

		b.append("<h3>Indicator strings referenced by actor code</h3><table>");
		int n = 0;
		for (StringInfo si : r.strings.values()) {
			if (!si.tags.isEmpty() && si.referencedByActor(r)) {
				b.append("<tr><td>").append(addrLink(si.address)).append("</td><td class=mono>")
						.append(esc(clip(si.value, 110))).append("</td><td class=dim>")
						.append(esc(String.join(", ", si.tags))).append("</td></tr>");
				if (++n >= 40) {
					break;
				}
			}
		}
		if (n == 0) {
			b.append("<tr><td class=dim>none</td></tr>");
		}
		b.append("</table>");

		if (!r.buildPaths.isEmpty()) {
			b.append("<h3>Actor source tree (from pclntab file paths)</h3><ul class=mono>");
			for (String p : r.buildPaths) {
				b.append("<li>").append(esc(p)).append("</li>");
			}
			b.append("</ul>");
		}
		if (!r.warnings.isEmpty() || !r.notes.isEmpty() || !s.kb.loadWarnings.isEmpty()) {
			b.append("<h3>Notes</h3><ul>");
			for (String w : r.warnings) {
				b.append("<li class=warn>").append(esc(w)).append("</li>");
			}
			for (String w : r.notes) {
				b.append("<li>").append(esc(w)).append("</li>");
			}
			for (String w : s.kb.loadWarnings) {
				b.append("<li class=warn>knowledge base: ").append(esc(w)).append("</li>");
			}
			b.append("</ul>");
		}
		b.append("<p class=dim>Knowledge base: ");
		for (Map.Entry<String, String> e : s.kb.sources.entrySet()) {
			b.append(esc(e.getKey())).append(" &larr; ").append(esc(e.getValue())).append("; ");
		}
		b.append("</p></body></html>");
		return b.toString();
	}

	private static String bar(int pct) {
		int w = Math.max(1, pct * 2);
		return "<span style=\"background-color:#7aa7d8\">" + "&nbsp;".repeat(Math.max(1, w / 6)) + "</span>";
	}

	private static void row(StringBuilder b, String k, String v) {
		rowHtml(b, k, esc(v));
	}

	private static void rowHtml(StringBuilder b, String k, String v) {
		b.append("<tr><td class=k>").append(esc(k)).append("</td><td>").append(v).append("</td></tr>");
	}

	private static String nz(String s) {
		return s == null ? "" : s;
	}

	// ------------------------------------------------------------------ function detail

	static String function(TriageSession s, FuncInfo f) {
		TriageResult r = s.result;
		StringBuilder b = new StringBuilder("<html><head>" + STYLE + "</head><body>");
		b.append("<h2>").append(esc(f.name())).append("</h2>");
		b.append("<table>");
		rowHtml(b, "Verdict", (f.isActor() ? "<b>Likely actor code</b>" : esc(f.category.label))
				+ " &mdash; category " + esc(f.category.label) + ", confidence " + f.actorConfidence + ", risk <b>" + f.risk
				+ "</b>" + (f.override != null ? " <span class=warn>(analyst override)</span>" : ""));
		rowHtml(b, "Address", addrLink(f.fn.entry()) + " &ndash; 0x" + Long.toHexString(f.fn.end()) + " (" + f.fn.size()
				+ " bytes)");
		row(b, "Package", f.packagePath());
		if (f.sym.receiver != null) {
			row(b, "Receiver", f.sym.receiver);
		}
		row(b, "Function", f.sym.shortName());
		if (!f.sourceLocation().isEmpty()) {
			row(b, "Source", f.sourceLocation());
		}
		if (!f.tags.isEmpty()) {
			row(b, "Tags", String.join(", ", f.tags));
		}
		if (f.libraryNote != null) {
			row(b, "Library", f.libraryNote);
		}
		b.append("</table>");

		b.append("<h3>Why this attribution</h3><ul>");
		for (String w : f.attributionReasons) {
			b.append("<li>").append(esc(w)).append("</li>");
		}
		b.append("</ul>");
		if (!f.riskReasons.isEmpty()) {
			b.append("<h3>Why it is interesting / suspicious</h3><ul>");
			for (String w : f.riskReasons) {
				b.append("<li>").append(esc(w)).append("</li>");
			}
			b.append("</ul>");
		}

		List<FuncInfo> meaningful = new ArrayList<>();
		int noise = 0;
		for (int c : f.callees) {
			FuncInfo cf = r.funcs.get(c);
			if (cf.category == Category.RUNTIME || cf.category == Category.GENERATED && !cf.isActorGenerated()) {
				noise++;
			}
			else {
				meaningful.add(cf);
			}
		}
		b.append("<h3>Calls (").append(meaningful.size()).append(" meaningful, ").append(noise)
				.append(" runtime/compiler noise hidden)</h3><ul>");
		meaningful.sort(Comparator.comparing((FuncInfo x) -> x.category.ordinal()).thenComparing(FuncInfo::name));
		for (FuncInfo cf : meaningful) {
			b.append("<li>").append(fnLink(cf)).append(" <span class=dim>[").append(cf.category.label);
			if (f.funcRefs.contains(cf.index)) {
				b.append(", func value");
			}
			b.append("]</span></li>");
		}
		b.append("</ul>");

		b.append("<h3>Called by (").append(f.callers.size()).append(")</h3><ul>");
		int k = 0;
		for (int c : f.callers) {
			FuncInfo cf = r.funcs.get(c);
			b.append("<li>").append(fnLink(cf)).append(" <span class=dim>[").append(cf.category.label).append("]</span></li>");
			if (++k >= 40) {
				b.append("<li class=dim>...</li>");
				break;
			}
		}
		b.append("</ul>");

		if (!f.strings.isEmpty()) {
			b.append("<h3>Strings (").append(f.strings.size()).append(")</h3><table>");
			for (long a : f.strings) {
				StringInfo si = r.strings.get(a);
				if (si == null) {
					continue;
				}
				b.append("<tr><td>").append(addrLink(a)).append("</td><td class=mono>").append(esc(clip(si.value, 140)))
						.append("</td><td class=dim>").append(esc(String.join(", ", si.tags))).append("</td></tr>");
			}
			b.append("</table>");
		}
		if (!f.typeRefs.isEmpty() && r.types != null) {
			b.append("<h3>Types used</h3><ul>");
			for (long a : f.typeRefs) {
				GoTypes.GoType t = r.types.all().get(a);
				if (t == null) {
					continue;
				}
				b.append("<li>").append(addrLink(a)).append(" <b>").append(esc(t.name)).append("</b> <span class=dim>")
						.append(t.kindName()).append("</span>");
				if (!t.fields.isEmpty()) {
					b.append(" { ").append(esc(String.join("; ", t.fields))).append(" }");
				}
				b.append("</li>");
			}
			b.append("</ul>");
		}
		b.append("</body></html>");
		return b.toString();
	}

	static String join(Collection<String> c) {
		return String.join(", ", c);
	}
}
