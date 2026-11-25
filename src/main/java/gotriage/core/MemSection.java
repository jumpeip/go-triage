package gotriage.core;

/**
 * One mapped region of the image.
 *
 * @param name section / block name (".text", ".rdata", ".gopclntab", ...)
 * @param start first virtual address
 * @param size size in bytes
 * @param read readable
 * @param write writable
 * @param execute executable
 * @param initialized backed by file bytes (false for .bss-like regions)
 */
public record MemSection(String name, long start, long size, boolean read, boolean write,
		boolean execute, boolean initialized) {

	public long end() {
		return start + size;
	}

	public boolean contains(long addr) {
		return Long.compareUnsigned(addr, start) >= 0 && Long.compareUnsigned(addr, end()) < 0;
	}

	/** Read-only, non-executable data (where Go keeps pclntab, rodata and type descriptors). */
	public boolean isReadOnlyData() {
		return read && !write && !execute && initialized;
	}
}
