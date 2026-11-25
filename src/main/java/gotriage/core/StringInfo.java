package gotriage.core;

import java.util.LinkedHashSet;
import java.util.Set;

/** A string literal referenced from code. */
public final class StringInfo {

	public final long address;
	public final String value;
	/** True when the exact length came from the code (Go strings aren't NUL-terminated). */
	public final boolean exactLength;
	public final Set<Integer> referencedBy = new LinkedHashSet<>();
	public final Set<String> tags = new LinkedHashSet<>();
	public final Set<String> caps = new LinkedHashSet<>();
	public int weight;

	public StringInfo(long address, String value, boolean exactLength) {
		this.address = address;
		this.value = value;
		this.exactLength = exactLength;
	}

	/** True when at least one referencing function is likely actor code. */
	public boolean referencedByActor(TriageResult r) {
		for (int i : referencedBy) {
			FuncInfo f = r.funcs.get(i);
			if (f.isActor() || f.isActorGenerated()) {
				return true;
			}
		}
		return false;
	}

	/** Best category among referrers (ACTOR beats UNKNOWN beats THIRD_PARTY ...). */
	public Category bestCategory(TriageResult r) {
		Category best = null;
		for (int i : referencedBy) {
			Category c = r.funcs.get(i).category;
			if (best == null || c.ordinal() < best.ordinal()) {
				best = c;
			}
		}
		return best == null ? Category.UNKNOWN : best;
	}
}
