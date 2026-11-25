package gotriage.core;

/**
 * One function recovered from the pclntab.
 *
 * @param index position in the functab
 * @param entry entry address
 * @param end exclusive end address (next function's entry)
 * @param name full Go symbol name as stored in the pclntab
 * @param file source file of the entry PC (null when unavailable)
 * @param line source line of the function start (0 when unavailable)
 * @param funcId runtime funcID (0 == normal function)
 * @param flag runtime funcFlag bits (TOPFRAME=1, SPWRITE=2, ASM=4 since Go 1.20)
 * @param args argument frame size
 */
public record GoFunc(int index, long entry, long end, String name, String file, int line,
		int funcId, int flag, int args) {

	public static final int FLAG_TOPFRAME = 1;
	public static final int FLAG_SPWRITE = 2;
	public static final int FLAG_ASM = 4;

	public long size() {
		return end - entry;
	}

	public boolean isAsm() {
		return (flag & FLAG_ASM) != 0;
	}
}
