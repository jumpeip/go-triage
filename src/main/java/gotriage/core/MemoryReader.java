package gotriage.core;

import java.util.List;

/**
 * Minimal view of a loaded binary image, addressed by virtual address. Implemented on top of a
 * Ghidra {@code Program} (plugin) and on top of a raw PE/ELF/Mach-O file (CLI), so every Go
 * parser in this package works identically in both places.
 */
public interface MemoryReader {

	/** @return true for big-endian targets */
	boolean isBigEndian();

	/** @return every mapped section/block, in address order */
	List<MemSection> sections();

	/**
	 * Reads up to {@code len} bytes at {@code addr}.
	 *
	 * @return the number of bytes actually read (0 when the address is unmapped)
	 */
	int read(long addr, byte[] dst, int off, int len);

	/** Processor family hint: "x86", "x86_64", "arm64", "arm", "mips", "ppc64", "riscv64" or "unknown". */
	String arch();

	/** Executable-format hint: "PE", "ELF", "MACHO" or "unknown". */
	String format();

	/**
	 * Finds the first occurrence of {@code pattern} in [{@code start}, {@code end}).
	 * The default implementation scans section data in chunks; implementations may override with
	 * something faster.
	 *
	 * @return the address of the match or -1
	 */
	default long find(byte[] pattern, long start, long end) {
		final int chunk = 1 << 20;
		byte[] buf = new byte[chunk + pattern.length];
		for (MemSection s : sections()) {
			if (!s.initialized()) {
				continue;
			}
			long lo = Math.max(start, s.start());
			long hi = Math.min(end, s.end());
			for (long a = lo; a < hi; a += chunk) {
				int want = (int) Math.min(chunk + pattern.length - 1, hi - a);
				int n = read(a, buf, 0, want);
				int idx = Bytes.indexOf(buf, n, pattern, 0);
				if (idx >= 0 && a + idx + pattern.length <= hi) {
					return a + idx;
				}
			}
		}
		return -1;
	}

	/** @return the section containing {@code addr} or null */
	default MemSection sectionAt(long addr) {
		for (MemSection s : sections()) {
			if (s.contains(addr)) {
				return s;
			}
		}
		return null;
	}

	/** @return true if {@code addr} lies in an initialized section */
	default boolean isMapped(long addr) {
		MemSection s = sectionAt(addr);
		return s != null && s.initialized();
	}

	/** @return true if {@code addr} lies in an executable section */
	default boolean isExecutable(long addr) {
		MemSection s = sectionAt(addr);
		return s != null && s.execute();
	}
}
