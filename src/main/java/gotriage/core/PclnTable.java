package gotriage.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Parser for the Go runtime's pclntab ("PC line table"), the structure that survives stripping
 * and gives every function's entry point, name, source file and line.
 * <p>
 * Supported layouts:
 * <ul>
 * <li>{@code 0xfffffffb} Go 1.2 - 1.15</li>
 * <li>{@code 0xfffffffa} Go 1.16 - 1.17</li>
 * <li>{@code 0xfffffff0} Go 1.18 - 1.19</li>
 * <li>{@code 0xfffffff1} Go 1.20+ (verified through go1.27)</li>
 * </ul>
 */
public final class PclnTable {

	public enum Version {
		V12(0xfffffffbL, "Go 1.2-1.15"),
		V116(0xfffffffaL, "Go 1.16-1.17"),
		V118(0xfffffff0L, "Go 1.18-1.19"),
		V120(0xfffffff1L, "Go 1.20+");

		public final long magic;
		public final String label;

		Version(long magic, String label) {
			this.magic = magic;
			this.label = label;
		}

		static Version of(long magic) {
			for (Version v : values()) {
				if (v.magic == magic) {
					return v;
				}
			}
			return null;
		}
	}

	public final long base;
	public final Version version;
	public final int minLC;
	public final int ptrSize;
	public final long nfunc;
	public final long nfiles;
	/** textStart field from the header (Go 1.18+); frequently 0 in PE files, see {@link #resolveTextStart}. */
	public final long headerTextStart;
	public final long funcnameTab;
	public final long cuTab;
	public final long fileTab;
	public final long pcTab;
	public final long functab;
	/** Go 1.2 only: file table (u32 offsets relative to base). */
	private final long fileTab12;

	private PclnTable(long base, Version version, int minLC, int ptrSize, long nfunc, long nfiles,
			long headerTextStart, long funcnameTab, long cuTab, long fileTab, long pcTab, long functab,
			long fileTab12) {
		this.base = base;
		this.version = version;
		this.minLC = minLC;
		this.ptrSize = ptrSize;
		this.nfunc = nfunc;
		this.nfiles = nfiles;
		this.headerTextStart = headerTextStart;
		this.funcnameTab = funcnameTab;
		this.cuTab = cuTab;
		this.fileTab = fileTab;
		this.pcTab = pcTab;
		this.functab = functab;
		this.fileTab12 = fileTab12;
	}

	/** Parses and sanity-checks the header at {@code addr}; returns null if it is not a pclntab. */
	public static PclnTable parseHeader(Mem m, long addr) {
		try {
			Version v = Version.of(m.u32(addr));
			if (v == null || m.u16(addr + 4) != 0) {
				return null;
			}
			int minLC = m.u8(addr + 6);
			int ps = m.u8(addr + 7);
			if ((minLC != 1 && minLC != 2 && minLC != 4) || (ps != 4 && ps != 8)) {
				return null;
			}
			m.setPtrSize(ps);
			long h = addr + 8;
			PclnTable t;
			switch (v) {
				case V12 -> {
					long nfunctab = m.ptr(h);
					long ft = h + ps;
					long filetaboff = m.u32(ft + nfunctab * 2 * ps + ps);
					t = new PclnTable(addr, v, minLC, ps, nfunctab, 0, 0, addr, 0, 0, addr, ft,
						addr + filetaboff);
				}
				case V116 -> {
					long nfunc = m.ptr(h);
					long nfiles = m.ptr(h + ps);
					t = new PclnTable(addr, v, minLC, ps, nfunc, nfiles, 0, addr + m.ptr(h + 2L * ps),
						addr + m.ptr(h + 3L * ps), addr + m.ptr(h + 4L * ps), addr + m.ptr(h + 5L * ps),
						addr + m.ptr(h + 6L * ps), 0);
				}
				default -> {
					long nfunc = m.ptr(h);
					long nfiles = m.ptr(h + ps);
					long text = m.ptr(h + 2L * ps);
					t = new PclnTable(addr, v, minLC, ps, nfunc, nfiles, text, addr + m.ptr(h + 3L * ps),
						addr + m.ptr(h + 4L * ps), addr + m.ptr(h + 5L * ps), addr + m.ptr(h + 6L * ps),
						addr + m.ptr(h + 7L * ps), 0);
				}
			}
			return t.validate(m) ? t : null;
		}
		catch (Mem.MemException | ArithmeticException e) {
			return null;
		}
	}

	private boolean validate(Mem m) {
		if (nfunc <= 0 || nfunc > 4_000_000) {
			return false;
		}
		if (version != Version.V12) {
			// offsets must be ordered: funcname < cu < file < pc < pcln
			if (!(funcnameTab < cuTab && cuTab <= fileTab && fileTab <= pcTab && pcTab < functab)) {
				return false;
			}
			if (functab - base > 1L << 31) {
				return false;
			}
		}
		// first two functab rows must be monotonic and the first func name printable
		try {
			long e0 = rawEntry(m, 0);
			long e1 = rawEntry(m, 1);
			if (Long.compareUnsigned(e1, e0) < 0) {
				return false;
			}
			for (int i = 0; i < Math.min(3, nfunc); i++) {
				String n = nameAt(m, funcStruct(m, i));
				if (n.isEmpty() || !isPlausibleName(n)) {
					return false;
				}
			}
			return true;
		}
		catch (Mem.MemException e) {
			return false;
		}
	}

	private static boolean isPlausibleName(String n) {
		for (int i = 0; i < n.length(); i++) {
			char c = n.charAt(i);
			if (c < 0x20 || c == 0x7f) {
				return false;
			}
		}
		return true;
	}

	/** Size of one functab row. */
	private int rowSize() {
		return (version == Version.V118 || version == Version.V120) ? 8 : 2 * ptrSize;
	}

	/** Entry from row {@code i}: an absolute PC for V12/V116, an offset from text for V118+. */
	private long rawEntry(Mem m, long i) {
		long row = functab + i * rowSize();
		return (version == Version.V118 || version == Version.V120) ? m.u32(row) : m.ptr(row);
	}

	private long funcStruct(Mem m, long i) {
		long row = functab + i * rowSize();
		return switch (version) {
			case V12 -> base + m.ptr(row + ptrSize);
			case V116 -> functab + m.ptr(row + ptrSize);
			default -> functab + m.u32(row + 4);
		};
	}

	private String nameAt(Mem m, long fs) {
		int nameOffPos = (version == Version.V118 || version == Version.V120) ? 4 : ptrSize;
		int nameoff = m.i32(fs + nameOffPos);
		long nameBase = version == Version.V12 ? base : funcnameTab;
		return m.cstring(nameBase + nameoff, 4096);
	}

	/** True when entry PCs are stored as offsets that need a text base. */
	public boolean needsTextBase() {
		return version == Version.V118 || version == Version.V120;
	}

	/**
	 * Picks the base for V118+ entry offsets: the header textStart when non-zero, else the
	 * moduledata text address, else the first executable section.
	 */
	public long resolveTextStart(MemoryReader r, Long moduledataText) {
		if (!needsTextBase()) {
			return 0;
		}
		List<Long> candidates = new ArrayList<>();
		if (headerTextStart != 0) {
			candidates.add(headerTextStart);
		}
		if (moduledataText != null && moduledataText != 0) {
			candidates.add(moduledataText);
		}
		for (MemSection s : r.sections()) {
			if (s.execute()) {
				candidates.add(s.start());
			}
		}
		for (long c : candidates) {
			if (r.isExecutable(c)) {
				return c;
			}
		}
		return candidates.isEmpty() ? 0 : candidates.get(0);
	}

	/** Reads every function. {@code textStart} is only used for Go 1.18+ tables. */
	public List<GoFunc> readFunctions(Mem m, long textStart, Progress progress) {
		int n = (int) nfunc;
		List<GoFunc> out = new ArrayList<>(n);
		boolean rel = needsTextBase();
		long prevEnd = 0;
		for (int i = 0; i < n; i++) {
			if (progress != null && (i & 0x3ff) == 0) {
				if (progress.isCancelled()) {
					break;
				}
				progress.update("Reading pclntab functions", i, n);
			}
			try {
				long entry = rawEntry(m, i);
				long next = rawEntry(m, i + 1);
				if (rel) {
					entry += textStart;
					next += textStart;
				}
				long fs = funcStruct(m, i);
				out.add(readFunc(m, i, fs, entry, next));
				prevEnd = next;
			}
			catch (Mem.MemException e) {
				// skip unreadable rows but keep going
			}
		}
		return out;
	}

	private GoFunc readFunc(Mem m, int idx, long fs, long entry, long end) {
		String name = nameAt(m, fs);
		int ps = ptrSize;
		int args, pcfile, pcln, cuOffset = 0, startLine = 0, funcId = 0, flag = 0;
		switch (version) {
			case V12 -> {
				// entry(ptr) nameoff args deferreturn pcsp pcfile pcln npcdata funcID _ _ nfuncdata
				long p = fs + ps;
				args = m.i32(p + 4);
				pcfile = (int) m.u32(p + 16);
				pcln = (int) m.u32(p + 20);
				funcId = 0; // only meaningful on >= 1.12; ignored to avoid misreading older tables
			}
			case V116 -> {
				long p = fs + ps;
				args = m.i32(p + 4);
				pcfile = (int) m.u32(p + 16);
				pcln = (int) m.u32(p + 20);
				cuOffset = (int) m.u32(p + 28);
				funcId = m.u8(p + 32);
			}
			case V118 -> {
				args = m.i32(fs + 8);
				pcfile = (int) m.u32(fs + 20);
				pcln = (int) m.u32(fs + 24);
				cuOffset = (int) m.u32(fs + 32);
				funcId = m.u8(fs + 36);
				flag = m.u8(fs + 37);
			}
			default -> {
				args = m.i32(fs + 8);
				pcfile = (int) m.u32(fs + 20);
				pcln = (int) m.u32(fs + 24);
				cuOffset = (int) m.u32(fs + 32);
				startLine = m.i32(fs + 36);
				funcId = m.u8(fs + 40);
				flag = m.u8(fs + 41);
			}
		}
		String file = null;
		int line = startLine;
		try {
			if (pcfile != 0) {
				int fileno = firstPcValue(m, pcfile);
				file = fileName(m, cuOffset, fileno);
			}
			if (line == 0 && pcln != 0) {
				line = firstPcValue(m, pcln);
			}
		}
		catch (Mem.MemException e) {
			// file/line are optional
		}
		return new GoFunc(idx, entry, end, name, file, Math.max(line, 0), funcId, flag, args);
	}

	/** Decodes the first value of a pcvalue table (the value at the function entry). */
	private int firstPcValue(Mem m, int off) {
		long tbl = (version == Version.V12 ? base : pcTab) + (off & 0xffffffffL);
		long[] uv = m.uvarint(tbl);
		long v = uv[0];
		long delta = (v >>> 1) ^ -(v & 1);
		return (int) (-1 + delta);
	}

	private String fileName(Mem m, int cuOffset, int fileno) {
		if (fileno < 0) {
			return null;
		}
		if (version == Version.V12) {
			long off = m.u32(fileTab12 + 4L * fileno);
			return m.cstring(base + off, 1024);
		}
		long off = m.u32(cuTab + 4L * ((cuOffset & 0xffffffffL) + fileno));
		if (off == 0xffffffffL) {
			return null;
		}
		return m.cstring(fileTab + off, 1024);
	}

	/**
	 * Locates the pclntab: well-known section names first, then a signature scan of the
	 * non-executable sections (then the executable ones as a last resort).
	 */
	public static PclnTable locate(Mem m) {
		MemoryReader r = m.reader();
		for (MemSection s : r.sections()) {
			String n = s.name().toLowerCase();
			if (n.equals(".gopclntab") || n.equals("__gopclntab") || n.endsWith("gopclntab")) {
				PclnTable t = parseHeader(m, s.start());
				if (t != null) {
					return t;
				}
			}
		}
		for (int pass = 0; pass < 2; pass++) {
			for (MemSection s : r.sections()) {
				if (!s.initialized() || (pass == 0) == s.execute()) {
					continue;
				}
				for (Version v : Version.values()) {
					byte[] pat = new byte[6];
					System.arraycopy(Bytes.u32Bytes(v.magic, r.isBigEndian()), 0, pat, 0, 4);
					long a = s.start();
					while (a >= 0 && a < s.end()) {
						long hit = r.find(pat, a, s.end());
						if (hit < 0) {
							break;
						}
						if ((hit & 3) == 0) {
							PclnTable t = parseHeader(m, hit);
							if (t != null) {
								return t;
							}
						}
						a = hit + 4;
					}
				}
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return String.format("pclntab@%s %s ptr=%d minLC=%d nfunc=%d", Bytes.hex(base), version.label,
			ptrSize, minLC, nfunc);
	}
}
