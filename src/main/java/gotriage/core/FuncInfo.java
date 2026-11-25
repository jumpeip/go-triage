package gotriage.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Analysis record for one pclntab function. */
public final class FuncInfo {

	public final int index;
	public final GoFunc fn;
	public final GoSymbol sym;

	public Category category = Category.UNKNOWN;
	/** Category of the owning package (differs from {@link #category} for generated code). */
	public Category ownerCategory = Category.UNKNOWN;
	public final Set<String> tags = new LinkedHashSet<>();
	/** 0-100: how sure we are this is author-written code. */
	public int actorConfidence;
	/** 0-100: how suspicious the function's behaviour is. */
	public int risk;
	/** Why the function was attributed the way it was. */
	public final List<String> attributionReasons = new ArrayList<>();
	/** Why it looks suspicious (capability evidence, combinations). */
	public final List<String> riskReasons = new ArrayList<>();

	/** capability -> first piece of evidence */
	public final Map<String, String> caps = new LinkedHashMap<>();
	/** capabilities reachable through actor-code callees (not including direct ones) */
	public final Map<String, String> transitiveCaps = new LinkedHashMap<>();

	public final Set<Integer> callees = new LinkedHashSet<>();
	public final Set<Integer> callers = new LinkedHashSet<>();
	/** callees reached through a function-value reference (closures, goroutines, callbacks) */
	public final Set<Integer> funcRefs = new LinkedHashSet<>();
	public final Set<Long> strings = new LinkedHashSet<>();
	public final Set<Long> typeRefs = new LinkedHashSet<>();
	/** Calls to runtime noise (bounds-check panics, morestack, write barriers, allocation helpers). */
	public int noiseCalls;

	/** Known-library note for the owning package. */
	public String libraryNote;
	/** Analyst override: null = none, TRUE = force actor, FALSE = force not actor. */
	public Boolean override;

	public FuncInfo(int index, GoFunc fn, GoSymbol sym) {
		this.index = index;
		this.fn = fn;
		this.sym = sym;
	}

	public String name() {
		return fn.name();
	}

	public String packagePath() {
		return sym.packagePath;
	}

	/** "Likely actor code": actor-like category (or override), not compiler-generated noise. */
	public boolean isActor() {
		if (override != null) {
			return override;
		}
		return category.isActorLike();
	}

	/** Generated code whose owning package is actor code (type eq/hash of actor types, -fm wrappers...). */
	public boolean isActorGenerated() {
		return category == Category.GENERATED && ownerCategory.isActorLike();
	}

	public Set<String> allCaps() {
		Set<String> s = new LinkedHashSet<>(caps.keySet());
		s.addAll(transitiveCaps.keySet());
		return s;
	}

	public String sourceLocation() {
		if (fn.file() == null) {
			return "";
		}
		return fn.line() > 0 ? fn.file() + ":" + fn.line() : fn.file();
	}
}
