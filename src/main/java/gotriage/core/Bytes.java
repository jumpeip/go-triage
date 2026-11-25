package gotriage.core;

import java.nio.charset.StandardCharsets;

/** Small byte-array helpers shared by the parsers and scanners. */
public final class Bytes {

	private Bytes() {
	}

	/** Naive search; patterns are short (4-16 bytes) so this is fast enough. */
	public static int indexOf(byte[] hay, int hayLen, byte[] needle, int from) {
		int last = hayLen - needle.length;
		outer:
		for (int i = Math.max(0, from); i <= last; i++) {
			for (int j = 0; j < needle.length; j++) {
				if (hay[i + j] != needle[j]) {
					continue outer;
				}
			}
			return i;
		}
		return -1;
	}

	public static int u32le(byte[] b, int o) {
		return (b[o] & 0xff) | (b[o + 1] & 0xff) << 8 | (b[o + 2] & 0xff) << 16 | (b[o + 3] & 0xff) << 24;
	}

	public static int u32(byte[] b, int o, boolean be) {
		if (!be) {
			return u32le(b, o);
		}
		return (b[o] & 0xff) << 24 | (b[o + 1] & 0xff) << 16 | (b[o + 2] & 0xff) << 8 | (b[o + 3] & 0xff);
	}

	public static byte[] u32Bytes(long v, boolean be) {
		byte[] r = new byte[4];
		for (int i = 0; i < 4; i++) {
			int shift = be ? (3 - i) * 8 : i * 8;
			r[i] = (byte) (v >>> shift);
		}
		return r;
	}

	public static byte[] ptrBytes(long v, int ptrSize, boolean be) {
		byte[] r = new byte[ptrSize];
		for (int i = 0; i < ptrSize; i++) {
			int shift = be ? (ptrSize - 1 - i) * 8 : i * 8;
			r[i] = (byte) (v >>> shift);
		}
		return r;
	}

	/** @return true if every byte is printable ASCII / common whitespace or valid UTF-8 text */
	public static boolean isMostlyText(byte[] b, int off, int len) {
		if (len <= 0) {
			return false;
		}
		int bad = 0;
		for (int i = off; i < off + len; i++) {
			int c = b[i] & 0xff;
			if (c == 0) {
				return false;
			}
			if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
				bad++;
			}
		}
		if (bad > 0) {
			return false;
		}
		// reject invalid UTF-8 sequences (round-trip test)
		String s = new String(b, off, len, StandardCharsets.UTF_8);
		return s.indexOf('�') < 0;
	}

	public static boolean isPrintableAscii(int c) {
		return c >= 0x20 && c < 0x7f;
	}

	public static String hex(long v) {
		return "0x" + Long.toHexString(v);
	}
}
