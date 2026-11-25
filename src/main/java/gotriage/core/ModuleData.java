package gotriage.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Locates {@code runtime.firstmoduledata} by searching data sections for a pointer to the
 * pclntab, then reads the version-stable fields (text range) plus, heuristically, the type
 * section range and typelinks table (removed/empty in recent Go releases).
 */
public final class ModuleData {

	public long address;
	public long text;
	public long etext;
	public long minpc;
	public long maxpc;
	public long types;
	public long etypes;
	public long typelinks;
	public long ntypelinks;

	public static ModuleData locate(Mem m, PclnTable pcln) {
		MemoryReader r = m.reader();
		int ps = pcln.ptrSize;
		byte[] pat = Bytes.ptrBytes(pcln.base, ps, r.isBigEndian());
		// data sections first, writable ones before read-only ones
		List<MemSection> order = new ArrayList<>();
		for (MemSection s : r.sections()) {
			if (s.initialized() && s.write() && !s.execute()) {
				order.add(s);
			}
		}
		for (MemSection s : r.sections()) {
			if (s.initialized() && !s.write() && !s.execute()) {
				order.add(s);
			}
		}
		for (MemSection s : order) {
			long a = s.start();
			while (a < s.end()) {
				long hit = r.find(pat, a, s.end());
				if (hit < 0) {
					break;
				}
				if (hit % ps == 0) {
					ModuleData md = tryParse(m, pcln, hit);
					if (md != null) {
						return md;
					}
				}
				a = hit + 1;
			}
		}
		return null;
	}

	private static ModuleData tryParse(Mem m, PclnTable pcln, long addr) {
		int ps = pcln.ptrSize;
		try {
			ModuleData md = new ModuleData();
			md.address = addr;
			if (pcln.version == PclnTable.Version.V12) {
				// pclntable []byte, ftab []functab, filetab []uint32, findfunctab, minpc, maxpc, text, etext
				long len = m.ptr(addr + ps);
				long cap = m.ptr(addr + 2L * ps);
				if (len == 0 || len != cap) {
					return null;
				}
				md.minpc = m.ptr(addr + 10L * ps);
				md.maxpc = m.ptr(addr + 11L * ps);
				md.text = m.ptr(addr + 12L * ps);
				md.etext = m.ptr(addr + 13L * ps);
			}
			else {
				// pcHeader, funcnametab, cutab, filetab, pctab, pclntable, ftab, findfunctab, minpc, maxpc, text, etext
				if (m.ptr(addr + ps) != pcln.funcnameTab) {
					return null;
				}
				if (m.ptr(addr + 4L * ps) != pcln.cuTab) {
					return null;
				}
				md.minpc = m.ptr(addr + 20L * ps);
				md.maxpc = m.ptr(addr + 21L * ps);
				md.text = m.ptr(addr + 22L * ps);
				md.etext = m.ptr(addr + 23L * ps);
			}
			if (Long.compareUnsigned(md.text, md.etext) > 0) {
				return null;
			}
			md.findTypes(m, ps, pcln.version == PclnTable.Version.V12 ? 14 : 24);
			return md;
		}
		catch (Mem.MemException e) {
			return null;
		}
	}

	/**
	 * Finds (types, etypes) as two consecutive words where types is the start of a read-only data
	 * section and etypes lies after it inside the same mapped area, then looks for a typelinks
	 * slice {ptr,len,cap} whose first offsets fall inside [types, etypes).
	 */
	private void findTypes(Mem m, int ps, int firstWord) {
		MemoryReader r = m.reader();
		int nwords = 96;
		long[] w = new long[nwords];
		for (int i = 0; i < nwords; i++) {
			try {
				w[i] = m.ptr(address + (long) (firstWord + i) * ps);
			}
			catch (Mem.MemException e) {
				w[i] = 0;
			}
		}
		for (int i = 0; i + 1 < nwords; i++) {
			long t = w[i];
			long et = w[i + 1];
			if (t == 0 || Long.compareUnsigned(et, t) <= 0 || et - t > 1L << 30) {
				continue;
			}
			MemSection s = r.sectionAt(t);
			if (s == null || s.execute() || s.write() || s.start() != t) {
				continue;
			}
			MemSection es = r.sectionAt(et - 1);
			if (es == null) {
				continue;
			}
			types = t;
			etypes = et;
			// typelinks: a slice after the types pair with len == cap
			for (int j = i + 2; j + 2 < nwords; j++) {
				long p = w[j];
				long len = w[j + 1];
				long cap = w[j + 2];
				if (p == 0 || len < 8 || len != cap || len > 4_000_000 || !r.isMapped(p)) {
					continue;
				}
				if (looksLikeTypelinks(m, p, len)) {
					typelinks = p;
					ntypelinks = len;
					break;
				}
			}
			return;
		}
	}

	private boolean looksLikeTypelinks(Mem m, long p, long len) {
		long span = etypes - types;
		try {
			int prev = -1;
			for (int k = 0; k < Math.min(len, 16); k++) {
				int off = m.i32(p + 4L * k);
				if (off <= prev || off < 0 || off >= span) {
					return false;
				}
				prev = off;
			}
			return true;
		}
		catch (Mem.MemException e) {
			return false;
		}
	}

	public boolean hasTypes() {
		return types != 0 && etypes > types;
	}

	public boolean inTypes(long a) {
		return hasTypes() && Long.compareUnsigned(a, types) >= 0 && Long.compareUnsigned(a, etypes) < 0;
	}
}
