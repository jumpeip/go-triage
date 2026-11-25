package gotriage.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Best-effort decoder for Go runtime type descriptors (internal/abi.Type, Go 1.16+). Types are
 * gathered from typelinks when present and from code references into the types section, so it
 * still works on new toolchains that no longer populate typelinks.
 */
public final class GoTypes {

	public static final String[] KINDS = { "invalid", "bool", "int", "int8", "int16", "int32",
		"int64", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "float32", "float64",
		"complex64", "complex128", "array", "chan", "func", "interface", "map", "pointer", "slice",
		"string", "struct", "unsafe.Pointer" };

	public static final int KIND_STRUCT = 25;
	public static final int KIND_POINTER = 22;

	/** A decoded type descriptor. */
	public static final class GoType {
		public final long address;
		public final String name;
		public final int kind;
		public final long size;
		/** For structs: "fieldName fieldType" entries. */
		public final List<String> fields = new ArrayList<>();
		/** Elem type address for pointers (0 otherwise). */
		public long elem;

		GoType(long address, String name, int kind, long size) {
			this.address = address;
			this.name = name;
			this.kind = kind;
			this.size = size;
		}

		public String kindName() {
			return kind >= 0 && kind < KINDS.length ? KINDS[kind] : "kind" + kind;
		}

		/** Package qualifier of the type name ("main" in "main.Config", "" for builtins). */
		public String packageName() {
			String n = name;
			while (n.startsWith("*") || n.startsWith("[]")) {
				n = n.startsWith("*") ? n.substring(1) : n.substring(2);
			}
			int dot = n.indexOf('.');
			int sp = n.indexOf(' ');
			int br = n.indexOf('[');
			if (dot <= 0 || (sp >= 0 && sp < dot) || (br >= 0 && br < dot)) {
				return "";
			}
			return n.substring(0, dot);
		}
	}

	private final Mem m;
	private final ModuleData md;
	private final int ps;
	private final boolean varintNames;
	private final Map<Long, GoType> cache = new LinkedHashMap<>();

	public GoTypes(Mem m, ModuleData md, int goMinor, PclnTable.Version v) {
		this.m = m;
		this.md = md;
		this.ps = m.ptrSize();
		// 1.17+ uses varint name lengths; 1.16 used a 2-byte big-endian length
		this.varintNames = goMinor >= 17 || (goMinor < 0 && v != PclnTable.Version.V116);
	}

	public boolean available() {
		return md != null && md.hasTypes();
	}

	public Map<Long, GoType> all() {
		return cache;
	}

	/** Decodes every typelinks entry (if the table exists). */
	public void loadTypelinks(Progress p) {
		if (!available() || md.typelinks == 0 || md.ntypelinks < 8) {
			return;
		}
		for (long i = 0; i < md.ntypelinks; i++) {
			if (p != null && (i & 0xff) == 0 && p.isCancelled()) {
				return;
			}
			try {
				int off = m.i32(md.typelinks + 4 * i);
				decode(md.types + off, 0);
			}
			catch (Mem.MemException e) {
				// ignore
			}
		}
	}

	/**
	 * Determines the base that type-descriptor name/type offsets are relative to. The field
	 * position of {@code types} in moduledata changes between Go releases (go1.27 added fields
	 * before it), so every pointer-sized word of moduledata that points into non-executable data
	 * is tried against code-referenced addresses, and the base that validates the most
	 * descriptors wins.
	 */
	public void calibrate(List<TriageResult.DataRef> refs, MemoryReader mr, int firstWord) {
		if (md == null) {
			return;
		}
		java.util.LinkedHashSet<Long> cands = new java.util.LinkedHashSet<>();
		if (md.types != 0) {
			cands.add(md.types);
		}
		for (int k = firstWord; k < firstWord + 96; k++) {
			try {
				long w = m.ptr(md.address + (long) k * ps);
				MemSection s = mr.sectionAt(w);
				if (s != null && !s.execute() && s.initialized()) {
					cands.add(w);
				}
			}
			catch (Mem.MemException e) {
				break;
			}
		}
		java.util.LinkedHashSet<Long> sample = new java.util.LinkedHashSet<>();
		for (TriageResult.DataRef ref : refs) {
			if (ref.length() == -1) {
				MemSection s = mr.sectionAt(ref.target());
				if (s != null && !s.execute() && s.initialized()) {
					sample.add(ref.target());
					if (sample.size() >= 800) {
						break;
					}
				}
			}
		}
		long best = 0;
		int bestCount = 0;
		for (long b : cands) {
			int count = 0;
			for (long t : sample) {
				if (Long.compareUnsigned(t, b) >= 0 && strictOk(t, b)) {
					count++;
				}
			}
			if (count > bestCount) {
				best = b;
				bestCount = count;
			}
		}
		if (bestCount >= 3) {
			MemSection s = mr.sectionAt(best);
			md.types = best;
			md.etypes = s.end();
			calibratedHits = bestCount;
		}
	}

	/** Number of sample descriptors that validated with the chosen base (0 = not calibrated). */
	public int calibratedHits;

	private boolean strictOk(long t, long base) {
		try {
			int align = m.u8(t + 2L * ps + 5);
			int fieldAlign = m.u8(t + 2L * ps + 6);
			int kind = m.u8(t + 2L * ps + 7) & 0x1f;
			if (kind == 0 || kind >= KINDS.length || !pow2(align) || !pow2(fieldAlign) || align > 64) {
				return false;
			}
			int str = m.i32(t + 4L * ps + 8);
			if (str <= 0) {
				return false;
			}
			String n = readName(base + str);
			if (n == null || !plausibleTypeName(n)) {
				return false;
			}
			int ptt = m.i32(t + 4L * ps + 12);
			if (ptt != 0) {
				int pk = m.u8(base + ptt + 2L * ps + 7) & 0x1f;
				if (pk != KIND_POINTER) {
					return false;
				}
			}
			return true;
		}
		catch (Mem.MemException e) {
			return false;
		}
	}

	private static boolean pow2(int v) {
		return v > 0 && (v & (v - 1)) == 0;
	}

	static boolean plausibleTypeName(String n) {
		if (n.isEmpty() || n.length() > 512) {
			return false;
		}
		char c0 = n.charAt(0);
		if (!(Character.isLetter(c0) || c0 == '*' || c0 == '[' || c0 == '_' || c0 == 'm' || c0 == 'f')) {
			return false;
		}
		for (int i = 0; i < n.length(); i++) {
			char c = n.charAt(i);
			if (c < 0x20 || c == 0x7f || c == '"' || c == '\\' || c == '<' || c == '>' || c == '|') {
				return false;
			}
		}
		return true;
	}

	/** Decodes the type descriptor at {@code addr}; returns null if it does not look like one. */
	public GoType decode(long addr, int depth) {
		if (!available() || !md.inTypes(addr)) {
			return null;
		}
		GoType cached = cache.get(addr);
		if (cached != null) {
			return cached;
		}
		try {
			if (!strictOk(addr, md.types)) {
				return null;
			}
			long size = m.ptr(addr);
			int tflag = m.u8(addr + 2L * ps + 4);
			int kind = m.u8(addr + 2L * ps + 7) & 0x1f;
			int strOff = m.i32(addr + 4L * ps + 8);
			String name = readName(md.types + strOff);
			if (name == null || name.isEmpty()) {
				return null;
			}
			if ((tflag & 2) != 0 && name.startsWith("*")) {
				name = name.substring(1); // tflagExtraStar
			}
			GoType t = new GoType(addr, name, kind, size);
			cache.put(addr, t);
			long typeEnd = addr + 4L * ps + 16; // sizeof(abi.Type)
			if (kind == KIND_POINTER) {
				t.elem = m.ptr(typeEnd);
			}
			else if (kind == KIND_STRUCT && depth < 2) {
				long fieldsPtr = m.ptr(typeEnd + ps);
				long nfields = m.ptr(typeEnd + 2L * ps);
				if (nfields > 0 && nfields < 512) {
					for (int i = 0; i < nfields; i++) {
						long f = fieldsPtr + (long) i * 3 * ps;
						String fname = readName(m.ptr(f));
						long ftyp = m.ptr(f + ps);
						GoType ft = decode(ftyp, depth + 1);
						t.fields.add((fname == null ? "?" : fname) + " " + (ft == null ? "?" : ft.name));
					}
				}
			}
			return t;
		}
		catch (Mem.MemException e) {
			return null;
		}
	}

	private String readName(long a) {
		if (a == 0) {
			return null;
		}
		try {
			long len;
			long data;
			if (varintNames) {
				long[] uv = m.uvarint(a + 1);
				len = uv[0];
				data = a + 1 + uv[1];
			}
			else {
				len = (m.u8(a + 1) << 8) | m.u8(a + 2);
				data = a + 3;
			}
			if (len <= 0 || len > 4096) {
				return null;
			}
			byte[] b = m.bytes(data, (int) len);
			if (!Bytes.isMostlyText(b, 0, b.length)) {
				return null;
			}
			return new String(b, java.nio.charset.StandardCharsets.UTF_8);
		}
		catch (Mem.MemException e) {
			return null;
		}
	}
}
