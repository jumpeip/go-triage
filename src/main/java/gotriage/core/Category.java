package gotriage.core;

/** Where a function's code most likely came from. */
public enum Category {
	ACTOR("Actor", "Author-written code (package main / main module / unattributed local code)"),
	UNKNOWN("Unknown", "Non-standard code that couldn't be attributed to a known dependency (likely actor)"),
	THIRD_PARTY("Third-party", "Dependency module / known library"),
	STDLIB("Stdlib", "Go standard library"),
	RUNTIME("Runtime", "Go runtime, scheduler, GC, memory and low-level support"),
	GENERATED("Generated", "Compiler/linker-generated: wrappers, type eq/hash, linker markers");

	public final String label;
	public final String description;

	Category(String label, String description) {
		this.label = label;
		this.description = description;
	}

	/** True for the categories an analyst should focus on. */
	public boolean isActorLike() {
		return this == ACTOR || this == UNKNOWN;
	}

	/** True for code that is almost never worth reading during triage. */
	public boolean isNoise() {
		return this == RUNTIME || this == GENERATED || this == STDLIB;
	}

	@Override
	public String toString() {
		return label;
	}
}
