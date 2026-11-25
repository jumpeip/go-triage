// Go Triage (headless / batch): triage the current Go program, optionally apply markup, and
// write JSON, CSV, Markdown and YARA reports.
//
// Script arguments (all optional):
//   arg0  output directory (default: the user's home directory)
//   arg1  "apply" to write functions/names/namespaces/tags/bookmarks/comments into the program
//   arg2  "actor-only" to restrict the JSON/CSV reports to likely actor code
//
// Example:
//   analyzeHeadless D:\proj Triage -import sample.exe -postScript GoTriageHeadless.java D:\out apply
//
//@category Go
//@menupath
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import gotriage.core.Category;
import gotriage.core.FuncInfo;
import gotriage.core.KnowledgeBase;
import gotriage.core.Reports;
import gotriage.core.TriageEngine;
import gotriage.core.TriageResult;
import gotriage.core.YaraGenerator;
import gotriage.ghidra.MarkupApplier;
import gotriage.ghidra.TriageSession;

public class GoTriageHeadless extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File outDir = new File(args.length > 0 ? args[0] : System.getProperty("user.home"));
		boolean apply = args.length > 1 && args[1].equalsIgnoreCase("apply");
		boolean actorOnly = args.length > 2 && args[2].equalsIgnoreCase("actor-only");
		outDir.mkdirs();

		KnowledgeBase kb = TriageSession.loadKnowledge();
		TriageSession s;
		try {
			s = TriageSession.run(currentProgram, kb, true, monitor);
		}
		catch (TriageEngine.NotGoBinaryException e) {
			println("GoTriage: " + currentProgram.getName() + ": " + e.getMessage());
			return;
		}
		TriageResult r = s.result;
		println(String.format("GoTriage: %s %s %s/%s - %d functions (refs: %s)", r.binaryName, r.goVersion(),
			r.format, r.arch, r.funcs.size(), r.refSource));
		StringBuilder counts = new StringBuilder("GoTriage: categories");
		for (Category c : Category.values()) {
			counts.append(' ').append(c.label).append('=').append(r.categoryCounts.getOrDefault(c, 0));
		}
		println(counts.toString());
		println("GoTriage: " + s.missingFunctions + " pclntab functions without a Ghidra function, "
			+ s.chunks.size() + " Ghidra fragments inside pclntab functions");

		if (apply) {
			MarkupApplier.Options o = new MarkupApplier.Options();
			o.colors = false; // needs the GUI colorizer service
			MarkupApplier m = new MarkupApplier(s, o, null);
			m.apply(monitor);
			for (String line : m.log()) {
				println("GoTriage: " + line);
			}
		}

		String base = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_");
		write(outDir, base + ".gotriage.json", Reports.json(r, actorOnly));
		write(outDir, base + ".gotriage.csv", Reports.csv(r, actorOnly));
		write(outDir, base + ".gotriage.md", Reports.markdown(r, 50));
		write(outDir, base + ".gotriage.yar", YaraGenerator.generate(r, null));

		int shown = 0;
		for (FuncInfo f : Reports.triageOrder(r)) {
			if (!f.isActor() || shown++ >= 15) {
				break;
			}
			println(String.format("  %-14s risk=%3d conf=%3d %s  %s", "0x" + Long.toHexString(f.fn.entry()), f.risk,
				f.actorConfidence, f.name(), String.join(",", f.allCaps())));
		}
	}

	private void write(File dir, String name, String text) throws Exception {
		Path p = new File(dir, name).toPath();
		Files.writeString(p, text, StandardCharsets.UTF_8);
		println("GoTriage: wrote " + p);
	}
}
