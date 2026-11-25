package gotriage.core;

/**
 * Collects code references (calls, data references) for the functions of a {@link TriageResult}.
 * Implementations: {@link ByteScanner} (decoder-free, x86/x86-64/ARM64) and the Ghidra-backed
 * collector in the plugin, which uses the program's references and instructions.
 */
public interface RefCollector {

	/** @return short description for the report ("byte scanner", "Ghidra references"...) */
	String name();

	/**
	 * Adds calls via {@link TriageResult#addCall}, function-value references via
	 * {@link TriageResult#addFuncRef} and data references via {@link TriageResult#addDataRef}.
	 */
	void collect(TriageResult r, Progress p);
}
