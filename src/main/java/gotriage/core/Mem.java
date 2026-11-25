package gotriage.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Endian-aware typed reads over a {@link MemoryReader} with a small page cache (the Ghidra
 * memory API is comparatively slow for the many tiny reads the pclntab walk performs).
 */
public final class Mem {

	/** Thrown when a read touches unmapped memory. */
	public static final class MemException extends RuntimeException {
		public MemException(String msg) {
			super(msg);
		}
	}

	private static final int PAGE = 4096;
	private static final int MAX_PAGES = 2048;

	private final MemoryReader reader;
	private final boolean be;
	private int ptrSize = 8;

	@SuppressWarnings("serial")
	private final Map<Long, byte[]> cache = new LinkedHashMap<>(256, 0.75f, true) {
		@Override
		protected boolean removeEldestEntry(Map.Entry<Long, byte[]> e) {
			return size() > MAX_PAGES;
		}
	};

	public Mem(MemoryReader reader) {
		this.reader = reader;
		this.be = reader.isBigEndian();
	}

	public MemoryReader reader() {
		return reader;
	}

	public boolean bigEndian() {
		return be;
	}

	public int ptrSize() {
		return ptrSize;
	}

	public void setPtrSize(int ps) {
		this.ptrSize = ps;
	}

	private byte[] page(long pageAddr) {
		byte[] p = cache.get(pageAddr);
		if (p == null) {
			p = new byte[PAGE];
			int n = reader.read(pageAddr, p, 0, PAGE);
			if (n < PAGE) {
				// partially mapped page: mark tail invalid by keeping the shorter array
				byte[] q = new byte[Math.max(n, 0)];
				System.arraycopy(p, 0, q, 0, q.length);
				p = q;
			}
			cache.put(pageAddr, p);
		}
		return p;
	}

	/** Reads exactly {@code n} bytes or throws. */
	public byte[] bytes(long addr, int n) {
		byte[] out = new byte[n];
		int done = 0;
		while (done < n) {
			long a = addr + done;
			long pa = a & ~(long) (PAGE - 1);
			int po = (int) (a - pa);
			byte[] p = page(pa);
			int avail = p.length - po;
			if (avail <= 0) {
				// page cache miss due to partial page or page straddling a section edge;
				// fall back to a direct read
				int got = reader.read(a, out, done, n - done);
				if (got <= 0) {
					throw new MemException("unmapped read at " + Bytes.hex(a));
				}
				done += got;
				continue;
			}
			int take = Math.min(avail, n - done);
			System.arraycopy(p, po, out, done, take);
			done += take;
		}
		return out;
	}

	/** @return true if {@code n} bytes at {@code addr} are readable */
	public boolean readable(long addr, int n) {
		try {
			bytes(addr, n);
			return true;
		}
		catch (MemException e) {
			return false;
		}
	}

	public int u8(long a) {
		return bytes(a, 1)[0] & 0xff;
	}

	public int u16(long a) {
		byte[] b = bytes(a, 2);
		return be ? ((b[0] & 0xff) << 8 | (b[1] & 0xff)) : ((b[1] & 0xff) << 8 | (b[0] & 0xff));
	}

	public long u32(long a) {
		return Bytes.u32(bytes(a, 4), 0, be) & 0xffffffffL;
	}

	public int i32(long a) {
		return Bytes.u32(bytes(a, 4), 0, be);
	}

	public long u64(long a) {
		byte[] b = bytes(a, 8);
		long v = 0;
		for (int i = 0; i < 8; i++) {
			int idx = be ? i : 7 - i;
			v = (v << 8) | (b[idx] & 0xff);
		}
		return v;
	}

	public long ptr(long a) {
		return ptrSize == 8 ? u64(a) : u32(a);
	}

	/** Reads a uvarint; returns {value, bytesConsumed}. */
	public long[] uvarint(long a) {
		long result = 0;
		int shift = 0;
		for (int i = 0; i < 10; i++) {
			int b = u8(a + i);
			result |= (long) (b & 0x7f) << shift;
			if (b < 0x80) {
				return new long[] { result, i + 1 };
			}
			shift += 7;
		}
		throw new MemException("bad varint at " + Bytes.hex(a));
	}

	/** NUL-terminated string, at most {@code max} bytes, decoded as UTF-8. */
	public String cstring(long a, int max) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream(64);
		for (int i = 0; i < max; i++) {
			int c;
			try {
				c = u8(a + i);
			}
			catch (MemException e) {
				break;
			}
			if (c == 0) {
				break;
			}
			bos.write(c);
		}
		return bos.toString(StandardCharsets.UTF_8);
	}

	/** Raw UTF-8 decode of exactly {@code len} bytes. */
	public String utf8(long a, int len) {
		return new String(bytes(a, len), StandardCharsets.UTF_8);
	}
}
