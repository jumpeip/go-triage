package gotriage.ghidra;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import gotriage.core.MemSection;
import gotriage.core.MemoryReader;

/** {@link MemoryReader} over a Ghidra program's default address space. */
public final class ProgramMemoryReader implements MemoryReader {

	private final Program program;
	private final Memory mem;
	private final AddressSpace space;
	private final List<MemSection> sections = new ArrayList<>();
	private final String arch;
	private final String format;

	public ProgramMemoryReader(Program program) {
		this.program = program;
		this.mem = program.getMemory();
		this.space = program.getAddressFactory().getDefaultAddressSpace();
		for (MemoryBlock b : mem.getBlocks()) {
			if (b.isOverlay() || b.isExternalBlock() || !b.getStart().getAddressSpace().equals(space)) {
				continue;
			}
			sections.add(new MemSection(b.getName(), b.getStart().getOffset(), b.getSize(), b.isRead(), b.isWrite(),
				b.isExecute(), b.isInitialized()));
		}
		sections.sort((a, c) -> Long.compareUnsigned(a.start(), c.start()));
		this.arch = archOf(program.getLanguage());
		String ef = program.getExecutableFormat();
		ef = ef == null ? "" : ef;
		this.format = ef.contains("PE") || ef.contains("Portable") ? "PE"
				: ef.contains("ELF") ? "ELF"
				: ef.contains("Mach") ? "MACHO" : ef;
	}

	private static String archOf(Language l) {
		String proc = l.getProcessor().toString().toLowerCase();
		int size = l.getLanguageDescription().getSize();
		if (proc.contains("x86")) {
			return size == 64 ? "x86_64" : "x86";
		}
		if (proc.contains("aarch64")) {
			return "arm64";
		}
		if (proc.equals("arm")) {
			return "arm";
		}
		if (proc.contains("mips")) {
			return "mips";
		}
		if (proc.contains("powerpc") || proc.contains("ppc")) {
			return "ppc64";
		}
		if (proc.contains("risc")) {
			return "riscv64";
		}
		return proc;
	}

	public Program program() {
		return program;
	}

	public Address addr(long a) {
		return space.getAddress(a);
	}

	@Override
	public boolean isBigEndian() {
		return program.getLanguage().isBigEndian();
	}

	@Override
	public List<MemSection> sections() {
		return sections;
	}

	@Override
	public int read(long addr, byte[] dst, int off, int len) {
		try {
			Address a = space.getAddress(addr);
			int n = mem.getBytes(a, dst, off, len);
			return Math.max(n, 0);
		}
		catch (MemoryAccessException | RuntimeException e) {
			// partial reads across block boundaries: fall back to byte-wise
			int done = 0;
			try {
				for (; done < len; done++) {
					dst[off + done] = mem.getByte(space.getAddress(addr + done));
				}
			}
			catch (MemoryAccessException | RuntimeException e2) {
				// stop at the first unreadable byte
			}
			return done;
		}
	}

	@Override
	public long find(byte[] pattern, long start, long end) {
		try {
			Address s = space.getAddress(start);
			Address e = space.getAddress(Math.max(start, end - 1));
			Address hit = mem.findBytes(s, e, pattern, null, true, TaskMonitor.DUMMY);
			return hit == null ? -1 : hit.getOffset();
		}
		catch (RuntimeException ex) {
			return MemoryReader.super.find(pattern, start, end);
		}
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
