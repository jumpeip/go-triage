package gotriage.core;

import java.util.Collection;
import java.util.Map;

/** Minimal streaming JSON writer (no external dependencies). */
public final class Json {

	private final StringBuilder sb = new StringBuilder(1 << 16);
	private final boolean[] first = new boolean[256];
	private int depth;

	public Json beginObject() {
		value();
		sb.append('{');
		first[++depth] = true;
		return this;
	}

	public Json endObject() {
		depth--;
		sb.append('}');
		return this;
	}

	public Json beginArray() {
		value();
		sb.append('[');
		first[++depth] = true;
		return this;
	}

	public Json endArray() {
		depth--;
		sb.append(']');
		return this;
	}

	public Json name(String n) {
		comma();
		str(n);
		sb.append(':');
		pendingValueAfterName = true;
		return this;
	}

	private boolean pendingValueAfterName;

	private void comma() {
		if (!first[depth]) {
			sb.append(',');
		}
		first[depth] = false;
	}

	private void value() {
		if (pendingValueAfterName) {
			pendingValueAfterName = false;
		}
		else if (depth > 0) {
			comma();
		}
	}

	public Json v(String s) {
		value();
		if (s == null) {
			sb.append("null");
		}
		else {
			str(s);
		}
		return this;
	}

	public Json v(long n) {
		value();
		sb.append(n);
		return this;
	}

	public Json v(boolean b) {
		value();
		sb.append(b);
		return this;
	}

	public Json kv(String k, String v) {
		return name(k).v(v);
	}

	public Json kv(String k, long v) {
		return name(k).v(v);
	}

	public Json kv(String k, boolean v) {
		return name(k).v(v);
	}

	public Json kv(String k, Collection<String> c) {
		name(k).beginArray();
		for (String s : c) {
			v(s);
		}
		return endArray();
	}

	public Json kv(String k, Map<String, String> m) {
		name(k).beginObject();
		for (Map.Entry<String, String> e : m.entrySet()) {
			kv(e.getKey(), e.getValue());
		}
		return endObject();
	}

	private void str(String s) {
		sb.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		sb.append('"');
	}

	@Override
	public String toString() {
		return sb.toString();
	}
}
