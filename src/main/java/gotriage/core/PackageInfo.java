package gotriage.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Aggregate view of one Go package. */
public final class PackageInfo {

	public final String path;
	public Category category = Category.UNKNOWN;
	public int confidence;
	public final List<String> reasons = new ArrayList<>();
	public final List<Integer> funcs = new ArrayList<>();
	public final Set<String> files = new LinkedHashSet<>();
	public final Set<String> caps = new LinkedHashSet<>();
	public GoBuildInfo.Module module;
	public KnowledgeBase.Library library;
	public int actorFuncs;
	public int maxRisk;
	public long codeBytes;

	public PackageInfo(String path) {
		this.path = path;
	}

	public String moduleLabel() {
		if (module == null) {
			return "";
		}
		return module.path() + (module.version() != null ? "@" + module.version() : "")
				+ (module.replacedBy() != null ? " => " + module.replacedBy() : "");
	}
}
