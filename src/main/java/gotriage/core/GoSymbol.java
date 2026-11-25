package gotriage.core;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Splits a Go linker symbol name into package path, receiver and function, and recognises the
 * compiler/linker-generated forms (type equality/hash routines, wrappers, closures, generic
 * instantiations, init tasks, linker markers).
 * <p>
 * Rules: the package path ends at the first '.' after the last '/' (the linker escapes dots in
 * the last path element as %2e, e.g. {@code gopkg.in/yaml%2ev3}); generic instantiation brackets
 * may contain '/' and '.' so they are masked before splitting.
 */
public final class GoSymbol {

	/** Shape of the symbol. */
	public enum Kind {
		FUNCTION, METHOD, CLOSURE, TYPE_EQ, TYPE_HASH, TYPE_OTHER, LINKER, NATIVE
	}

	public final String full;
	public final String packagePath;
	/** Last element of the package path ("cmd" for github.com/x/y/cmd). */
	public final String packageName;
	/** Receiver type without parentheses ("*Client" or "Client"), or null. */
	public final String receiver;
	/** Function or method name, with closure suffixes. */
	public final String func;
	public final Kind kind;
	public final Set<String> tags = new LinkedHashSet<>();

	private static final Pattern CLOSURE = Pattern.compile("\\.func\\d+(\\.\\d+)*");
	private static final Pattern GOWRAP = Pattern.compile("\\.gowrap\\d+");
	private static final Pattern DEFERWRAP = Pattern.compile("\\.deferwrap\\d+");
	private static final Pattern RANGEFUNC = Pattern.compile("-range\\d+");
	private static final Pattern INIT = Pattern.compile("^init(\\.\\d+)?$");
	private static final Pattern INIT_CLOSURE = Pattern.compile("^init(\\.\\d+)?\\.func\\d+.*");
	private static final Pattern LEGACY_LINKER = Pattern.compile(
		"go\\.(buildid|itab|string|func|info|cuinfo|importpath|link|plugin|track|map|constinfo|loc|range|"
				+ "debuglines|builtin|interface|typelink|runtimeinfo|weak|textfips)\\b");
	private static final Pattern NOT_METHOD_SUFFIX =
		Pattern.compile("^(func\\d+|\\d+|gowrap\\d+|deferwrap\\d+)([.\\-].*)?$");

	private GoSymbol(String full, String pkg, String recv, String func, Kind kind) {
		this.full = full;
		this.packagePath = pkg;
		int slash = pkg.lastIndexOf('/');
		this.packageName = slash >= 0 ? pkg.substring(slash + 1) : pkg;
		this.receiver = recv;
		this.func = func;
		this.kind = kind;
	}

	public static GoSymbol parse(String name) {
		if (name == null) {
			name = "";
		}
		// linker markers and other non-code symbols (go:buildid, go:textfipsstart, legacy go.buildid,
		// go.itab.*). Careful: go.uber.org/..., go.opentelemetry.io/... are real packages.
		if (name.startsWith("go:") || LEGACY_LINKER.matcher(name).lookingAt()) {
			GoSymbol s = new GoSymbol(name, "", null, name, Kind.LINKER);
			s.tags.add("linker-marker");
			return s;
		}
		// type routines: type:.eq.T / type..eq.T / type:.hash.T / type..hash.T
		for (String[] pfx : new String[][] { { "type:.eq.", "type-eq" }, { "type..eq.", "type-eq" },
			{ "type:.hash.", "type-hash" }, { "type..hash.", "type-hash" } }) {
			if (name.startsWith(pfx[0])) {
				String t = name.substring(pfx[0].length());
				GoSymbol s = new GoSymbol(name, packageOfTypeExpr(t), null, name,
					pfx[1].equals("type-eq") ? Kind.TYPE_EQ : Kind.TYPE_HASH);
				s.tags.add(pfx[1]);
				s.tags.add("type-metadata");
				return s;
			}
		}
		if (name.startsWith("type:") || name.startsWith("type..")) {
			GoSymbol s = new GoSymbol(name, "", null, name, Kind.TYPE_OTHER);
			s.tags.add("type-metadata");
			return s;
		}

		String masked = maskBrackets(name);
		int lastSlash = masked.lastIndexOf('/');
		int dot = masked.indexOf('.', lastSlash + 1);
		if (dot <= 0) {
			GoSymbol s = new GoSymbol(name, "", null, name, Kind.NATIVE);
			s.tags.add(name.startsWith("_cgo_") || name.startsWith("x_cgo") || name.startsWith("crosscall")
					? "cgo"
					: "native");
			return s;
		}
		String pkg = name.substring(0, dot).replace("%2e", ".").replace("%2E", ".");
		String rest = name.substring(dot + 1);
		String maskedRest = masked.substring(dot + 1);

		String recv = null;
		String func = rest;
		Kind kind = Kind.FUNCTION;
		if (maskedRest.startsWith("(")) {
			int close = maskedRest.indexOf(')');
			if (close > 0) {
				recv = rest.substring(1, close);
				func = close + 2 <= rest.length() ? rest.substring(close + 2) : "";
				kind = Kind.METHOD;
			}
		}
		else {
			// value-receiver method: Type.Method. Go identifiers can't contain '.', so a second
			// component that is not a closure/init/wrapper suffix must be a method name.
			int d2 = maskedRest.indexOf('.');
			if (d2 > 0) {
				String first = rest.substring(0, d2);
				String second = maskedRest.substring(d2 + 1);
				if (!NOT_METHOD_SUFFIX.matcher(second).matches() && !first.equals("init")) {
					recv = first;
					func = rest.substring(d2 + 1);
					kind = Kind.METHOD;
				}
			}
		}
		GoSymbol s = new GoSymbol(name, pkg, recv, func, kind);
		s.addShapeTags(maskedRest);
		return s;
	}

	private void addShapeTags(String maskedRest) {
		Matcher cm = CLOSURE.matcher(maskedRest);
		boolean closure = cm.find();
		if (closure) {
			tags.add("closure");
		}
		if (GOWRAP.matcher(maskedRest).find()) {
			tags.add("gowrap");
			tags.add("goroutine-launch");
			closure = true;
		}
		if (DEFERWRAP.matcher(maskedRest).find()) {
			tags.add("deferwrap");
			closure = true;
		}
		if (RANGEFUNC.matcher(maskedRest).find()) {
			tags.add("range-func");
			closure = true;
		}
		if (maskedRest.endsWith("-fm")) {
			tags.add("method-value-wrapper");
			tags.add("wrapper");
		}
		if (full.contains("[")) {
			tags.add("generic");
			if (full.contains("go.shape.")) {
				tags.add("generic-shape-instance");
			}
		}
		String f = func;
		if (INIT.matcher(f).matches()) {
			tags.add("init");
		}
		else if (INIT_CLOSURE.matcher(f).matches()) {
			tags.add("init");
		}
		if (kind == Kind.METHOD) {
			tags.add("method");
		}
		if (packagePath.equals("main") && func.equals("main")) {
			tags.add("entry-point");
		}
		if (closure && kind == Kind.FUNCTION) {
			// leave kind as FUNCTION for the enclosing name; closure tagged separately
		}
	}

	/** True for closures, gowrap/deferwrap/range-func bodies. */
	public boolean isClosure() {
		return tags.contains("closure") || tags.contains("gowrap") || tags.contains("deferwrap")
				|| tags.contains("range-func");
	}

	/** The enclosing named function of a closure ("main.run" for "main.run.func1.2"). */
	public String enclosingFunction() {
		String m = maskBrackets(full);
		int lastSlash = m.lastIndexOf('/');
		int cut = -1;
		for (String marker : new String[] { ".func", ".gowrap", ".deferwrap", "-range" }) {
			int i = m.indexOf(marker, lastSlash + 1);
			if (i > 0 && (cut < 0 || i < cut)) {
				cut = i;
			}
		}
		return cut > 0 ? full.substring(0, cut) : full;
	}

	/** Short display name: "(*T).M", "F", "F.func1". */
	public String shortName() {
		if (kind == Kind.METHOD && receiver != null) {
			return (receiver.startsWith("*") ? "(" + receiver + ")" : receiver) + "." + func;
		}
		return func;
	}

	/** Replaces the contents of balanced [...] with '#' so '/' and '.' inside don't confuse splitting. */
	static String maskBrackets(String s) {
		StringBuilder b = new StringBuilder(s.length());
		int depth = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '[') {
				depth++;
				b.append(c);
			}
			else if (c == ']') {
				depth = Math.max(0, depth - 1);
				b.append(c);
			}
			else {
				b.append(depth > 0 ? '#' : c);
			}
		}
		return b.toString();
	}

	/** Package of a type expression ("*main.Config" -> "main", "[2]interface {}" -> ""). */
	static String packageOfTypeExpr(String t) {
		String s = t;
		while (true) {
			if (s.startsWith("*")) {
				s = s.substring(1);
			}
			else if (s.startsWith("[]")) {
				s = s.substring(2);
			}
			else if (s.startsWith("[")) {
				int c = s.indexOf(']');
				if (c < 0) {
					break;
				}
				s = s.substring(c + 1);
			}
			else {
				break;
			}
		}
		if (s.startsWith("struct") || s.startsWith("interface") || s.startsWith("func(")
				|| s.startsWith("map[") || s.startsWith("chan ")) {
			return "";
		}
		String masked = maskBrackets(s);
		int lastSlash = masked.lastIndexOf('/');
		int dot = masked.indexOf('.', lastSlash + 1);
		if (dot <= 0) {
			return "";
		}
		return s.substring(0, dot).replace("%2e", ".");
	}

	@Override
	public String toString() {
		return full;
	}
}
