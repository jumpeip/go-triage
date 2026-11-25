package gotriage.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Tab-separated, analyst-editable rule files. Each file is read from an override directory when
 * present (the extension's {@code data/} folder or a user folder) and otherwise from the copy
 * bundled in the jar under {@code /gotriage/data/}.
 */
public final class KnowledgeBase {

	public static final String STDLIB = "stdlib_packages.txt";
	public static final String LIBRARIES = "known_libraries.tsv";
	public static final String CAP_RULES = "capability_rules.tsv";
	public static final String STRING_RULES = "string_rules.tsv";
	public static final String CAPABILITIES = "capabilities.tsv";
	public static final String[] FILES = { STDLIB, LIBRARIES, CAP_RULES, STRING_RULES, CAPABILITIES };

	/** Library entry: prefix, class (library / dual-use / offensive), capabilities, description. */
	public record Library(String prefix, String libClass, List<String> caps, String description) {
		public boolean isNotable() {
			return !"library".equals(libClass);
		}
	}

	/** Callee-name rule. */
	public record CapRule(String kind, String pattern, Pattern regex, String capability,
			String description) {
		boolean matches(String fullName, String pkg) {
			return switch (kind) {
				case "pkg" -> pkg.equals(pattern) || pkg.startsWith(pattern + "/") || pkg.startsWith(pattern + ".");
				case "func" -> fullName.startsWith(pattern);
				case "re" -> regex.matcher(fullName).find();
				default -> false;
			};
		}
	}

	/** String rule. */
	public record StringRule(Pattern regex, String tag, String capability, int weight,
			String description) {
	}

	/** Capability metadata. */
	public record Capability(String name, int weight, String description) {
	}

	public final Set<String> stdTop = new HashSet<>();
	public final List<String> runtimePrefixes = new ArrayList<>();
	public final List<Library> libraries = new ArrayList<>();
	public final List<CapRule> capRules = new ArrayList<>();
	public final List<StringRule> stringRules = new ArrayList<>();
	public final Map<String, Capability> capabilities = new LinkedHashMap<>();
	public final List<String> loadWarnings = new ArrayList<>();
	public final Map<String, String> sources = new HashMap<>();

	public static KnowledgeBase load(Path overrideDir) {
		List<Path> dirs = new ArrayList<>();
		if (overrideDir != null) {
			dirs.add(overrideDir);
		}
		return load(dirs);
	}

	/** Loads each file from the first directory that has it, else from the bundled copy. */
	public static KnowledgeBase load(List<Path> dirs) {
		KnowledgeBase kb = new KnowledgeBase();
		kb.loadStd(kb.lines(dirs, STDLIB));
		kb.loadCapabilities(kb.lines(dirs, CAPABILITIES));
		kb.loadLibraries(kb.lines(dirs, LIBRARIES));
		kb.loadCapRules(kb.lines(dirs, CAP_RULES));
		kb.loadStringRules(kb.lines(dirs, STRING_RULES));
		return kb;
	}

	private List<String> lines(List<Path> dirs, String file) {
		List<String> out = new ArrayList<>();
		for (Path dir : dirs) {
			Path f = dir.resolve(file);
			try {
				if (Files.isRegularFile(f)) {
					out.addAll(Files.readAllLines(f, StandardCharsets.UTF_8));
					sources.put(file, f.toString());
					return out;
				}
			}
			catch (IOException e) {
				loadWarnings.add("Could not read " + f + ": " + e.getMessage());
			}
		}
		try (InputStream in = KnowledgeBase.class.getResourceAsStream("/gotriage/data/" + file)) {
			if (in == null) {
				loadWarnings.add("Missing knowledge file " + file);
				return out;
			}
			try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
				String l;
				while ((l = br.readLine()) != null) {
					out.add(l);
				}
			}
			sources.put(file, "(bundled)");
		}
		catch (IOException e) {
			loadWarnings.add("Could not read bundled " + file + ": " + e.getMessage());
		}
		return out;
	}

	private static boolean skip(String l) {
		String t = l.strip();
		return t.isEmpty() || t.startsWith("#");
	}

	private void loadStd(List<String> lines) {
		String section = "std";
		for (String l : lines) {
			if (skip(l)) {
				continue;
			}
			String t = l.strip();
			if (t.startsWith("[") && t.endsWith("]")) {
				section = t.substring(1, t.length() - 1);
				continue;
			}
			if (section.equals("runtime")) {
				runtimePrefixes.add(t);
			}
			else {
				stdTop.add(t);
			}
		}
	}

	private void loadCapabilities(List<String> lines) {
		for (String l : lines) {
			if (skip(l)) {
				continue;
			}
			String[] f = l.split("\t");
			if (f.length < 2) {
				continue;
			}
			try {
				capabilities.put(f[0].strip(), new Capability(f[0].strip(), Integer.parseInt(f[1].strip()),
					f.length > 2 ? f[2].strip() : ""));
			}
			catch (NumberFormatException e) {
				loadWarnings.add(CAPABILITIES + ": bad weight in: " + l);
			}
		}
	}

	private void loadLibraries(List<String> lines) {
		for (String l : lines) {
			if (skip(l)) {
				continue;
			}
			String[] f = l.split("\t");
			if (f.length < 2) {
				continue;
			}
			List<String> caps = new ArrayList<>();
			if (f.length > 2 && !f[2].isBlank() && !f[2].strip().equals("-")) {
				for (String c : f[2].split(",")) {
					caps.add(c.strip());
				}
			}
			libraries.add(new Library(f[0].strip(), f[1].strip(), caps, f.length > 3 ? f[3].strip() : ""));
		}
		// longest prefix first so lookups find the most specific entry
		libraries.sort((a, b) -> b.prefix().length() - a.prefix().length());
	}

	private void loadCapRules(List<String> lines) {
		for (String l : lines) {
			if (skip(l)) {
				continue;
			}
			String[] f = l.split("\t");
			if (f.length < 2) {
				continue;
			}
			String m = f[0].strip();
			int colon = m.indexOf(':');
			if (colon < 0) {
				continue;
			}
			String kind = m.substring(0, colon);
			String pat = m.substring(colon + 1);
			Pattern re = null;
			if (kind.equals("re")) {
				try {
					re = Pattern.compile(pat);
				}
				catch (PatternSyntaxException e) {
					loadWarnings.add(CAP_RULES + ": bad regex " + pat);
					continue;
				}
			}
			capRules.add(new CapRule(kind, pat, re, f[1].strip(), f.length > 2 ? f[2].strip() : ""));
		}
	}

	private void loadStringRules(List<String> lines) {
		for (String l : lines) {
			if (skip(l)) {
				continue;
			}
			String[] f = l.split("\t");
			if (f.length < 4) {
				continue;
			}
			try {
				stringRules.add(new StringRule(Pattern.compile(f[0]), f[1].strip(),
					f[2].strip().equals("-") ? null : f[2].strip(), Integer.parseInt(f[3].strip()),
					f.length > 4 ? f[4].strip() : ""));
			}
			catch (PatternSyntaxException | NumberFormatException e) {
				loadWarnings.add(STRING_RULES + ": bad rule: " + l);
			}
		}
	}

	// ---------------------------------------------------------------- queries

	public boolean isRuntimePackage(String pkg) {
		for (String p : runtimePrefixes) {
			if (p.endsWith("/") ? pkg.startsWith(p) : (pkg.equals(p) || pkg.startsWith(p + "/"))) {
				return true;
			}
		}
		return false;
	}

	/** Standard library: first path element is a known std root and contains no '.' */
	public boolean isStdPackage(String pkg) {
		if (pkg.isEmpty()) {
			return false;
		}
		int slash = pkg.indexOf('/');
		String first = slash < 0 ? pkg : pkg.substring(0, slash);
		if (first.contains(".")) {
			return false;
		}
		return stdTop.contains(first);
	}

	public Library libraryFor(String pkg) {
		for (Library l : libraries) {
			String p = l.prefix();
			if (pkg.equals(p) || pkg.startsWith(p.endsWith("/") ? p : p + "/")) {
				return l;
			}
		}
		return null;
	}

	public int weight(String capability) {
		Capability c = capabilities.get(capability);
		return c == null ? 5 : c.weight();
	}

	public String describe(String capability) {
		Capability c = capabilities.get(capability);
		return c == null ? capability : c.description();
	}
}
