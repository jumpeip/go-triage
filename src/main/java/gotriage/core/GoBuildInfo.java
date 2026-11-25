package gotriage.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the {@code "\xff Go buildinf:"} blob (runtime/debug.BuildInfo): Go version, main
 * package path, main module, every dependency module with version/sum, replacements and build
 * settings (GOOS, GOARCH, CGO_ENABLED, -ldflags, vcs.* ...).
 */
public final class GoBuildInfo {

	/** A module line ("mod" or "dep"). */
	public record Module(String path, String version, String sum, String replacedBy) {
	}

	public long address;
	public String goVersion;
	/** "path" line: import path of the main package. */
	public String mainPackagePath;
	public Module mainModule;
	public final List<Module> deps = new ArrayList<>();
	public final Map<String, String> settings = new LinkedHashMap<>();
	public String rawModinfo;

	private static final byte[] MAGIC = "ÿ Go buildinf:".getBytes(StandardCharsets.ISO_8859_1);

	/** Locates and parses build info; returns null if absent. */
	public static GoBuildInfo locate(Mem m) {
		MemoryReader r = m.reader();
		for (MemSection s : r.sections()) {
			if (!s.initialized()) {
				continue;
			}
			long a = s.start();
			while (a < s.end()) {
				long hit = r.find(MAGIC, a, s.end());
				if (hit < 0) {
					break;
				}
				GoBuildInfo bi = parseAt(m, hit);
				if (bi != null) {
					return bi;
				}
				a = hit + 1;
			}
		}
		return null;
	}

	static GoBuildInfo parseAt(Mem m, long addr) {
		try {
			int ps = m.u8(addr + 14);
			int flags = m.u8(addr + 15);
			if (ps != 4 && ps != 8) {
				return null;
			}
			GoBuildInfo bi = new GoBuildInfo();
			bi.address = addr;
			String vers;
			String mod;
			if ((flags & 2) != 0) {
				// Go 1.18+: inline varint-prefixed strings at +32
				long p = addr + 32;
				long[] l1 = m.uvarint(p);
				p += l1[1];
				vers = m.utf8(p, (int) l1[0]);
				p += l1[0];
				long[] l2 = m.uvarint(p);
				p += l2[1];
				mod = l2[0] > 0 && l2[0] < 8 << 20 ? m.utf8(p, (int) l2[0]) : "";
			}
			else {
				// pointer to a Go string header {ptr,len}
				int savedPs = m.ptrSize();
				m.setPtrSize(ps);
				try {
					vers = readGoStringHeader(m, m.ptr(addr + 16));
					mod = readGoStringHeader(m, m.ptr(addr + 16 + ps));
				}
				finally {
					m.setPtrSize(savedPs);
				}
			}
			if (vers == null || !vers.startsWith("go") && !vers.startsWith("devel")) {
				return null;
			}
			bi.goVersion = vers;
			bi.parseModinfo(mod == null ? "" : mod);
			return bi;
		}
		catch (Mem.MemException e) {
			return null;
		}
	}

	private static String readGoStringHeader(Mem m, long hdr) {
		if (hdr == 0) {
			return null;
		}
		long p = m.ptr(hdr);
		long len = m.ptr(hdr + m.ptrSize());
		if (len <= 0 || len > 8 << 20) {
			return "";
		}
		return m.utf8(p, (int) len);
	}

	void parseModinfo(String s) {
		// strip the 16-byte sentinels that wrap modinfo
		if (s.length() >= 33 && s.charAt(s.length() - 17) == '\n') {
			s = s.substring(16, s.length() - 16);
		}
		rawModinfo = s;
		Module last = null;
		for (String line : s.split("\n")) {
			String[] f = line.split("\t");
			if (f.length == 0) {
				continue;
			}
			switch (f[0]) {
				case "path" -> mainPackagePath = f.length > 1 ? f[1] : null;
				case "mod" -> {
					mainModule = new Module(get(f, 1), get(f, 2), get(f, 3), null);
					last = mainModule;
				}
				case "dep" -> {
					Module d = new Module(get(f, 1), get(f, 2), get(f, 3), null);
					deps.add(d);
					last = d;
				}
				case "=>" -> {
					if (last != null) {
						String repl = get(f, 1) + (get(f, 2) != null ? " " + get(f, 2) : "");
						Module rep = new Module(last.path(), last.version(), last.sum(), repl);
						if (last == mainModule) {
							mainModule = rep;
						}
						else {
							deps.set(deps.size() - 1, rep);
						}
						last = rep;
					}
				}
				case "build" -> {
					if (f.length > 1) {
						String kv = line.substring(line.indexOf('\t') + 1);
						int eq = kv.indexOf('=');
						if (eq > 0) {
							String v = kv.substring(eq + 1);
							if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
								v = v.substring(1, v.length() - 1).replace("\\\"", "\"");
							}
							settings.put(kv.substring(0, eq), v);
						}
					}
				}
				default -> {
				}
			}
		}
	}

	private static String get(String[] f, int i) {
		return i < f.length && !f[i].isEmpty() ? f[i] : null;
	}

	/** @return the main module path, falling back to the main package path */
	public String mainModulePath() {
		if (mainModule != null && mainModule.path() != null) {
			return mainModule.path();
		}
		return mainPackagePath;
	}

	/** @return the dependency module that owns {@code pkg} (longest prefix match) or null */
	public Module depFor(String pkg) {
		Module best = null;
		for (Module d : deps) {
			String p = d.path();
			if (p != null && (pkg.equals(p) || pkg.startsWith(p + "/"))) {
				if (best == null || p.length() > best.path().length()) {
					best = d;
				}
			}
		}
		return best;
	}

	/** @return true when {@code pkg} belongs to the main module */
	public boolean inMainModule(String pkg) {
		String mm = mainModulePath();
		if (mm == null || mm.isEmpty() || mm.equals("command-line-arguments")) {
			return false;
		}
		return pkg.equals(mm) || pkg.startsWith(mm + "/");
	}

	/** Go minor version (e.g. 22 for go1.22.3), or -1. */
	public int goMinor() {
		return parseMinor(goVersion);
	}

	public static int parseMinor(String v) {
		if (v == null) {
			return -1;
		}
		int i = v.indexOf("go1.");
		if (i < 0) {
			return -1;
		}
		int j = i + 4;
		int k = j;
		while (k < v.length() && Character.isDigit(v.charAt(k))) {
			k++;
		}
		try {
			return Integer.parseInt(v.substring(j, k));
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
}
