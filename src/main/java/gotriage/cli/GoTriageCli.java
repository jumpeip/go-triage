package gotriage.cli;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import gotriage.core.Bytes;
import gotriage.core.Category;
import gotriage.core.FuncInfo;
import gotriage.core.KnowledgeBase;
import gotriage.core.Progress;
import gotriage.core.Reports;
import gotriage.core.TriageEngine;
import gotriage.core.TriageResult;
import gotriage.core.YaraGenerator;

/**
 * Standalone command line front-end (no Ghidra needed).
 *
 * <pre>
 * java -cp go-triage.jar gotriage.cli.GoTriageCli [options] &lt;binary&gt;
 *   --json FILE      full JSON report
 *   --csv FILE       function table
 *   --md FILE        Markdown summary
 *   --yara FILE      draft YARA rule
 *   --actor-only     restrict JSON/CSV to likely actor code
 *   --kb DIR         knowledge-base override directory
 *   --top N          functions listed on stdout (default 25)
 *   --quiet          no stdout summary
 * </pre>
 */
public final class GoTriageCli {

	public static void main(String[] args) throws Exception {
		String json = null, csv = null, md = null, yara = null, kbDir = null, bin = null;
		boolean actorOnly = false, quiet = false;
		int top = 25;
		for (int i = 0; i < args.length; i++) {
			switch (args[i]) {
				case "--json" -> json = args[++i];
				case "--csv" -> csv = args[++i];
				case "--md" -> md = args[++i];
				case "--yara" -> yara = args[++i];
				case "--kb" -> kbDir = args[++i];
				case "--top" -> top = Integer.parseInt(args[++i]);
				case "--actor-only" -> actorOnly = true;
				case "--quiet" -> quiet = true;
				case "-h", "--help" -> {
					usage();
					return;
				}
				default -> bin = args[i];
			}
		}
		if (bin == null) {
			usage();
			System.exit(2);
		}
		long t0 = System.currentTimeMillis();
		KnowledgeBase kb = KnowledgeBase.load(kbDir == null ? null : Path.of(kbDir));
		for (String w : kb.loadWarnings) {
			System.err.println("kb: " + w);
		}
		Path p = Path.of(bin);
		RawImage img = new RawImage(p);
		TriageResult r;
		try {
			r = TriageEngine.run(img, kb, null, true, p.getFileName().toString(), Progress.NONE);
		}
		catch (TriageEngine.NotGoBinaryException e) {
			System.err.println(e.getMessage());
			System.exit(1);
			return;
		}
		long ms = System.currentTimeMillis() - t0;
		if (json != null) {
			Files.writeString(Path.of(json), Reports.json(r, actorOnly), StandardCharsets.UTF_8);
		}
		if (csv != null) {
			Files.writeString(Path.of(csv), Reports.csv(r, actorOnly), StandardCharsets.UTF_8);
		}
		if (md != null) {
			Files.writeString(Path.of(md), Reports.markdown(r, 40), StandardCharsets.UTF_8);
		}
		if (yara != null) {
			Files.writeString(Path.of(yara), YaraGenerator.generate(r, null), StandardCharsets.UTF_8);
		}
		if (!quiet) {
			summary(r, top, ms);
		}
	}

	private static void summary(TriageResult r, int top, long ms) {
		System.out.printf("%s  [%s %s]  %s  (%d ms)%n", r.binaryName, r.format, r.arch, r.goVersion(), ms);
		System.out.println("  " + r.pcln + "  text=" + Bytes.hex(r.textStart));
		if (r.moduledata != null) {
			System.out.printf("  moduledata@%s types=%s..%s typelinks=%d%n", Bytes.hex(r.moduledata.address),
				Bytes.hex(r.moduledata.types), Bytes.hex(r.moduledata.etypes), r.moduledata.ntypelinks);
		}
		if (r.buildInfo != null) {
			System.out.printf("  module=%s  path=%s  deps=%d%n", r.buildInfo.mainModulePath(),
				r.buildInfo.mainPackagePath, r.buildInfo.deps.size());
			for (Map.Entry<String, String> e : r.buildInfo.settings.entrySet()) {
				System.out.printf("    %s=%s%n", e.getKey(), e.getValue());
			}
		}
		System.out.println("  refs: " + r.refSource + "   goroot: " + r.goroot + "   trimpath: " + r.trimpath);
		if (r.garbleSuspected) {
			System.out.println("  GARBLE SUSPECTED: " + r.garbleEvidence);
		}
		if (!r.buildUsers.isEmpty()) {
			System.out.println("  build users: " + r.buildUsers);
		}
		for (String w : r.warnings) {
			System.out.println("  WARNING: " + w);
		}
		for (String w : r.notes) {
			System.out.println("  note: " + w);
		}
		System.out.print("  functions:");
		for (Category c : Category.values()) {
			System.out.printf(" %s=%d", c.label, r.categoryCounts.getOrDefault(c, 0));
		}
		System.out.printf("%n  strings=%d types=%d%n", r.strings.size(),
			r.types == null ? 0 : r.types.all().size());
		List<FuncInfo> fs = new ArrayList<>(r.actorFunctions());
		fs.sort(Comparator.comparing((FuncInfo f) -> -f.risk).thenComparing(f -> f.fn.entry()));
		System.out.printf("  likely actor functions: %d; top %d by risk:%n", fs.size(), Math.min(top, fs.size()));
		for (int i = 0; i < Math.min(top, fs.size()); i++) {
			FuncInfo f = fs.get(i);
			System.out.printf("    %-12s risk=%3d conf=%3d %-60s %s%n", Bytes.hex(f.fn.entry()), f.risk,
				f.actorConfidence, f.name().length() > 60 ? f.name().substring(0, 57) + "..." : f.name(),
				String.join(",", f.allCaps()));
		}
	}

	private static void usage() {
		System.out.println("""
			go-triage CLI - Go binary triage without Ghidra
			usage: java -cp go-triage.jar gotriage.cli.GoTriageCli [options] <binary>
			  --json FILE     full JSON report
			  --csv FILE      function table (CSV)
			  --md FILE       Markdown summary
			  --yara FILE     draft YARA rule from actor artefacts
			  --actor-only    restrict JSON/CSV to likely actor code
			  --kb DIR        knowledge-base override directory (default: bundled data)
			  --top N         actor functions listed on stdout (default 25)
			  --quiet         suppress the stdout summary""");
	}
}
