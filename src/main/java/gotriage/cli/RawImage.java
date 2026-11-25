package gotriage.cli;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import gotriage.core.MemSection;
import gotriage.core.MemoryReader;

/** Maps PE (32/64), ELF (32/64, LE/BE) and Mach-O 64 files to virtual addresses for the CLI. */
public final class RawImage implements MemoryReader {

	private record Region(MemSection sec, long fileOff, long fileSize) {
	}

	private final byte[] data;
	private final List<Region> regions = new ArrayList<>();
	private final List<MemSection> sections = new ArrayList<>();
	private boolean be;
	private String arch = "unknown";
	private String format = "unknown";

	public RawImage(Path p) throws IOException {
		this.data = Files.readAllBytes(p);
		ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
		if (data.length > 0x40 && data[0] == 'M' && data[1] == 'Z') {
			parsePE(bb);
		}
		else if (data.length > 0x34 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
			parseELF(bb);
		}
		else if (data.length > 0x20 && (bb.getInt(0) == 0xfeedfacf)) {
			parseMachO(bb);
		}
		else {
			throw new IOException("unsupported file format (expected PE, ELF or 64-bit Mach-O)");
		}
		regions.sort(Comparator.comparingLong(r -> r.sec().start()));
		for (Region r : regions) {
			sections.add(r.sec());
		}
	}

	private void parsePE(ByteBuffer bb) {
		format = "PE";
		int pe = bb.getInt(0x3c);
		int machine = bb.getShort(pe + 4) & 0xffff;
		arch = switch (machine) {
			case 0x8664 -> "x86_64";
			case 0x14c -> "x86";
			case 0xaa64 -> "arm64";
			case 0x1c0, 0x1c4 -> "arm";
			default -> "unknown";
		};
		int nsec = bb.getShort(pe + 6) & 0xffff;
		int optSize = bb.getShort(pe + 20) & 0xffff;
		int opt = pe + 24;
		int magic = bb.getShort(opt) & 0xffff;
		long imageBase = magic == 0x20b ? bb.getLong(opt + 24) : (bb.getInt(opt + 28) & 0xffffffffL);
		int sh = opt + optSize;
		for (int i = 0; i < nsec; i++) {
			int o = sh + i * 40;
			String name = cstr(o, 8);
			long vsize = bb.getInt(o + 8) & 0xffffffffL;
			long va = bb.getInt(o + 12) & 0xffffffffL;
			long rsize = bb.getInt(o + 16) & 0xffffffffL;
			long roff = bb.getInt(o + 20) & 0xffffffffL;
			int ch = bb.getInt(o + 36);
			long size = Math.max(vsize, rsize);
			boolean exec = (ch & 0x20000000) != 0;
			boolean read = (ch & 0x40000000) != 0;
			boolean write = (ch & 0x80000000) != 0;
			long fsz = Math.min(rsize, size);
			regions.add(new Region(new MemSection(name, imageBase + va, size, read, write, exec, fsz > 0),
				roff, fsz));
		}
	}

	private void parseELF(ByteBuffer bb) {
		format = "ELF";
		boolean is64 = data[4] == 2;
		be = data[5] == 2;
		bb.order(be ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		int machine = bb.getShort(18) & 0xffff;
		arch = switch (machine) {
			case 62 -> "x86_64";
			case 3 -> "x86";
			case 183 -> "arm64";
			case 40 -> "arm";
			case 8 -> "mips";
			case 21 -> "ppc64";
			case 243 -> "riscv64";
			case 22 -> "s390x";
			default -> "unknown";
		};
		long shoff = is64 ? bb.getLong(0x28) : bb.getInt(0x20) & 0xffffffffL;
		int shentsize = bb.getShort(is64 ? 0x3a : 0x2e) & 0xffff;
		int shnum = bb.getShort(is64 ? 0x3c : 0x30) & 0xffff;
		int shstrndx = bb.getShort(is64 ? 0x3e : 0x32) & 0xffff;
		if (shoff == 0 || shnum == 0) {
			parseElfSegments(bb, is64);
			return;
		}
		long strOff = 0;
		{
			int o = (int) (shoff + (long) shstrndx * shentsize);
			strOff = is64 ? bb.getLong(o + 0x18) : bb.getInt(o + 0x10) & 0xffffffffL;
		}
		for (int i = 0; i < shnum; i++) {
			int o = (int) (shoff + (long) i * shentsize);
			int nameOff = bb.getInt(o);
			int type = bb.getInt(o + 4);
			long flags = is64 ? bb.getLong(o + 8) : bb.getInt(o + 8) & 0xffffffffL;
			long addr = is64 ? bb.getLong(o + 0x10) : bb.getInt(o + 0x0c) & 0xffffffffL;
			long off = is64 ? bb.getLong(o + 0x18) : bb.getInt(o + 0x10) & 0xffffffffL;
			long size = is64 ? bb.getLong(o + 0x20) : bb.getInt(o + 0x14) & 0xffffffffL;
			if ((flags & 2) == 0 || addr == 0 || size == 0) {
				continue; // not SHF_ALLOC
			}
			boolean nobits = type == 8;
			String name = cstr((int) (strOff + nameOff), 64);
			regions.add(new Region(new MemSection(name, addr, size, true, (flags & 1) != 0, (flags & 4) != 0,
				!nobits), off, nobits ? 0 : size));
		}
	}

	private void parseElfSegments(ByteBuffer bb, boolean is64) {
		long phoff = is64 ? bb.getLong(0x20) : bb.getInt(0x1c) & 0xffffffffL;
		int phentsize = bb.getShort(is64 ? 0x36 : 0x2a) & 0xffff;
		int phnum = bb.getShort(is64 ? 0x38 : 0x2c) & 0xffff;
		for (int i = 0; i < phnum; i++) {
			int o = (int) (phoff + (long) i * phentsize);
			int type = bb.getInt(o);
			if (type != 1) {
				continue;
			}
			int flags = is64 ? bb.getInt(o + 4) : bb.getInt(o + 0x18);
			long off = is64 ? bb.getLong(o + 8) : bb.getInt(o + 4) & 0xffffffffL;
			long va = is64 ? bb.getLong(o + 0x10) : bb.getInt(o + 8) & 0xffffffffL;
			long fsz = is64 ? bb.getLong(o + 0x20) : bb.getInt(o + 0x10) & 0xffffffffL;
			long msz = is64 ? bb.getLong(o + 0x28) : bb.getInt(o + 0x14) & 0xffffffffL;
			regions.add(new Region(new MemSection("LOAD" + i, va, msz, (flags & 4) != 0, (flags & 2) != 0,
				(flags & 1) != 0, fsz > 0), off, fsz));
		}
	}

	private void parseMachO(ByteBuffer bb) {
		format = "MACHO";
		int cpu = bb.getInt(4);
		arch = cpu == 0x01000007 ? "x86_64" : cpu == 0x0100000c ? "arm64" : "unknown";
		int ncmds = bb.getInt(16);
		int o = 32;
		for (int c = 0; c < ncmds; c++) {
			int cmd = bb.getInt(o);
			int size = bb.getInt(o + 4);
			if (cmd == 0x19) {
				String seg = cstr(o + 8, 16);
				int nsects = bb.getInt(o + 64);
				int initprot = bb.getInt(o + 60);
				int s = o + 72;
				for (int k = 0; k < nsects; k++) {
					String sect = cstr(s, 16);
					long addr = bb.getLong(s + 32);
					long sz = bb.getLong(s + 40);
					long off = bb.getInt(s + 48) & 0xffffffffL;
					int flags = bb.getInt(s + 64);
					boolean zerofill = (flags & 0xff) == 1 || (flags & 0xff) == 0x0c;
					boolean exec = (initprot & 4) != 0 && sect.equals("__text");
					regions.add(new Region(new MemSection(sect, addr, sz, true, (initprot & 2) != 0, exec,
						!zerofill), off, zerofill ? 0 : sz));
					s += 80;
				}
			}
			o += size;
		}
	}

	private String cstr(int o, int max) {
		int e = o;
		while (e < o + max && e < data.length && data[e] != 0) {
			e++;
		}
		return new String(data, o, e - o, StandardCharsets.ISO_8859_1);
	}

	@Override
	public boolean isBigEndian() {
		return be;
	}

	@Override
	public List<MemSection> sections() {
		return sections;
	}

	@Override
	public int read(long addr, byte[] dst, int off, int len) {
		int done = 0;
		while (done < len) {
			long a = addr + done;
			Region r = regionAt(a);
			if (r == null) {
				break;
			}
			long rel = a - r.sec().start();
			if (rel >= r.fileSize()) {
				break; // uninitialised tail
			}
			int n = (int) Math.min(len - done, r.fileSize() - rel);
			long fo = r.fileOff() + rel;
			if (fo + n > data.length) {
				n = (int) Math.max(0, data.length - fo);
				if (n == 0) {
					break;
				}
			}
			System.arraycopy(data, (int) fo, dst, off + done, n);
			done += n;
		}
		return done;
	}

	private Region lastHit;

	private Region regionAt(long a) {
		Region h = lastHit;
		if (h != null && h.sec().contains(a)) {
			return h;
		}
		for (Region r : regions) {
			if (r.sec().contains(a)) {
				lastHit = r;
				return r;
			}
		}
		return null;
	}

	@Override
	public long find(byte[] pattern, long start, long end) {
		for (Region r : regions) {
			long lo = Math.max(start, r.sec().start());
			long hi = Math.min(end, r.sec().start() + r.fileSize());
			if (lo >= hi) {
				continue;
			}
			int from = (int) (r.fileOff() + (lo - r.sec().start()));
			int to = (int) Math.min(data.length, r.fileOff() + (hi - r.sec().start()));
			int idx = indexOf(data, from, to, pattern);
			if (idx >= 0) {
				return r.sec().start() + (idx - r.fileOff());
			}
		}
		return -1;
	}

	private static int indexOf(byte[] d, int from, int to, byte[] p) {
		byte first = p[0];
		int last = to - p.length;
		outer:
		for (int i = from; i <= last; i++) {
			if (d[i] != first) {
				continue;
			}
			for (int j = 1; j < p.length; j++) {
				if (d[i + j] != p[j]) {
					continue outer;
				}
			}
			return i;
		}
		return -1;
	}

	@Override
	public String arch() {
		return arch;
	}

	@Override
	public String format() {
		return format;
	}
}
