package gotriage.core;

/**
 * Decoder-free reference recovery. Go code generation is very regular, which makes byte
 * patterns reliable when every candidate is validated against pclntab function entries:
 * <ul>
 * <li>calls: {@code E8 rel32} / {@code E9 rel32} (x86/x86-64), {@code BL}/{@code B} (ARM64) whose
 * target is exactly a pclntab function entry</li>
 * <li>string literals: {@code LEA reg,[rip+disp]} (or ADRP+ADD on ARM64) followed by a small
 * {@code MOV reg, imm} that is the string length (Go strings aren't NUL-terminated)</li>
 * <li>func values: LEA of a rodata word that points at a function entry (closures/goroutines)</li>
 * </ul>
 * Everything else becomes a raw data reference for the engine to classify (string / type).
 */
public final class ByteScanner implements RefCollector {

	private final Mem m;
	private final boolean arm64;
	private final boolean x64;
	private final boolean x86;

	public ByteScanner(Mem m, String arch) {
		this.m = m;
		this.arm64 = "arm64".equals(arch);
		this.x64 = "x86_64".equals(arch);
		this.x86 = "x86".equals(arch);
	}

	public boolean supported() {
		return arm64 || x64 || x86;
	}

	@Override
	public String name() {
		return "byte scanner (" + (arm64 ? "ARM64" : x64 ? "x86-64" : x86 ? "x86" : "unsupported") + ")";
	}

	@Override
	public void collect(TriageResult r, Progress p) {
		if (!supported()) {
			return;
		}
		int n = r.funcs.size();
		for (int i = 0; i < n; i++) {
			if (p != null && (i & 0x3ff) == 0) {
				if (p.isCancelled()) {
					return;
				}
				p.update("Scanning code for calls and strings", i, n);
			}
			FuncInfo f = r.funcs.get(i);
			long size = f.fn.size();
			if (size <= 0 || size > 8 << 20) {
				continue;
			}
			byte[] b;
			try {
				b = m.bytes(f.fn.entry(), (int) size);
			}
			catch (Mem.MemException e) {
				continue;
			}
			if (arm64) {
				scanArm64(r, f, b);
			}
			else {
				scanX86(r, f, b);
			}
		}
	}

	// ------------------------------------------------------------------ x86 / x86-64

	private void scanX86(TriageResult r, FuncInfo f, byte[] b) {
		long base = f.fn.entry();
		int n = b.length;
		for (int i = 0; i + 5 <= n; i++) {
			int op = b[i] & 0xff;
			if (op == 0xE8 || op == 0xE9) {
				long tgt = base + i + 5 + Bytes.u32le(b, i + 1);
				if (!x64) {
					tgt &= 0xffffffffL;
				}
				int callee = r.funcAtEntry(tgt);
				if (callee >= 0 && callee != f.index) {
					r.addCall(f.index, callee);
				}
				continue;
			}
			if (x64 && i + 7 <= n && (op == 0x48 || op == 0x4C) && (b[i + 1] & 0xff) == 0x8D
					&& (b[i + 2] & 0xC7) == 0x05) {
				// LEA r64, [rip+disp32]
				long tgt = base + i + 7 + Bytes.u32le(b, i + 3);
				int len = findLenX86(b, i + 7);
				dataRef(r, f, tgt, len);
				i += 6;
				continue;
			}
			if (x64 && i + 7 <= n && (op == 0x48 || op == 0x4C) && (b[i + 1] & 0xff) == 0x8B
					&& (b[i + 2] & 0xC7) == 0x05) {
				// MOV r64, [rip+disp32]: possibly a global string variable {ptr,len}
				long tgt = base + i + 7 + Bytes.u32le(b, i + 3);
				MemSection s = m.reader().sectionAt(tgt);
				if (s != null && s.initialized() && !s.execute()) {
					r.addDataRef(f.index, tgt, -2);
				}
				i += 6;
				continue;
			}
			if (x86 && i + 6 <= n && op == 0x8D && (b[i + 1] & 0xC7) == 0x05) {
				// LEA r32, [disp32]
				long tgt = Bytes.u32le(b, i + 2) & 0xffffffffL;
				int len = findLenX86(b, i + 6);
				dataRef(r, f, tgt, len);
				i += 5;
			}
		}
	}

	/** Looks for a string-length immediate in the next few instructions. */
	private static int findLenX86(byte[] b, int from) {
		int lim = Math.min(b.length, from + 28);
		for (int j = from; j < lim; j++) {
			int c = b[j] & 0xff;
			// mov r32, imm32 (optionally REX.B)
			if (c >= 0xB8 && c <= 0xBF && j + 5 <= b.length) {
				int prev = j > from ? b[j - 1] & 0xff : 0;
				if (prev == 0x41 || prev != 0x48 && prev != 0x49) {
					int v = Bytes.u32le(b, j + 1);
					if (v > 0 && v <= 0x20000) {
						return v;
					}
				}
			}
			// REX.W mov r64, imm32 : 48/49 C7 C0+r imm32
			if ((c == 0x48 || c == 0x49) && j + 7 <= b.length && (b[j + 1] & 0xff) == 0xC7
					&& (b[j + 2] & 0xF8) == 0xC0) {
				int v = Bytes.u32le(b, j + 3);
				if (v > 0 && v <= 0x20000) {
					return v;
				}
			}
			// mov r/m, imm32 : C7 /0 — stack slots (Go < 1.17 stack ABI) or struct fields
			// (e.g. 48 C7 44 24 08 imm32, 48 C7 40 10 imm32)
			if (c == 0xC7 && j + 2 < b.length) {
				int modrm = b[j + 1] & 0xff;
				int mod = modrm >>> 6;
				int reg = (modrm >>> 3) & 7;
				int rm = modrm & 7;
				if (reg == 0 && mod != 3) {
					int extra = (rm == 4 ? 1 : 0)
							+ (mod == 1 ? 1 : mod == 2 ? 4 : (rm == 5 ? 4 : 0));
					int immAt = j + 2 + extra;
					if (immAt + 4 <= b.length) {
						int v = Bytes.u32le(b, immAt);
						if (v > 0 && v <= 0x20000) {
							return v;
						}
					}
				}
			}
			// stop at a call: the length must be set before the call
			if (c == 0xE8 && j > from) {
				break;
			}
		}
		return -1;
	}

	// ------------------------------------------------------------------ ARM64

	private void scanArm64(TriageResult r, FuncInfo f, byte[] b) {
		long base = f.fn.entry();
		boolean be = m.bigEndian();
		int n = b.length & ~3;
		for (int i = 0; i + 4 <= n; i += 4) {
			int w = Bytes.u32(b, i, be);
			long pc = base + i;
			int top = w & 0xFC000000;
			if (top == 0x94000000 || top == 0x14000000) {
				long off = ((long) (w << 6) >> 6) << 2; // sign-extend imm26
				int callee = r.funcAtEntry(pc + off);
				if (callee >= 0 && callee != f.index) {
					r.addCall(f.index, callee);
				}
				continue;
			}
			if ((w & 0x9F000000) == 0x90000000 && i + 8 <= n) {
				// ADRP xd, page
				int rd = w & 31;
				long immlo = (w >>> 29) & 3;
				long immhi = (w >>> 5) & 0x7FFFF;
				long imm = (immhi << 2) | immlo;
				imm = (imm << 43) >> 43; // sign-extend 21 bits
				long page = (pc & ~0xFFFL) + (imm << 12);
				int w2 = Bytes.u32(b, i + 4, be);
				// ADD xd, xd, #imm12{, lsl 12}
				if ((w2 & 0xFF800000) == 0x91000000 && ((w2 >>> 5) & 31) == rd) {
					long imm12 = (w2 >>> 10) & 0xFFF;
					int sh = (w2 >>> 22) & 1;
					long tgt = page + (imm12 << (sh * 12));
					int len = findLenArm64(b, i + 8, be);
					dataRef(r, f, tgt, len);
					i += 4;
				}
				// LDR xt, [xd, #imm12*8]: global variable load (possible string header)
				else if ((w2 & 0xFFC00000) == 0xF9400000 && ((w2 >>> 5) & 31) == rd) {
					long tgt = page + (((w2 >>> 10) & 0xFFFL) << 3);
					MemSection s = m.reader().sectionAt(tgt);
					if (s != null && s.initialized() && !s.execute()) {
						r.addDataRef(f.index, tgt, -2);
					}
					i += 4;
				}
			}
		}
	}

	private static int findLenArm64(byte[] b, int from, boolean be) {
		int lim = Math.min(b.length - 4, from + 16);
		for (int j = from; j <= lim; j += 4) {
			int w = Bytes.u32(b, j, be);
			// MOVZ wd/xd, #imm16 (hw = 0)
			if ((w & 0x7F800000) == 0x52800000 && ((w >>> 21) & 3) == 0) {
				int v = (w >>> 5) & 0xFFFF;
				if (v > 0) {
					return v;
				}
			}
			// ORR xd, xzr, #imm (logical immediate) - only decode the simple low-run forms
			if ((w & 0x7F8003E0) == 0x320003E0) {
				int v = decodeLogicalImm(w);
				if (v > 0 && v <= 0x20000) {
					return v;
				}
			}
			if ((w & 0xFC000000) == 0x94000000) {
				break;
			}
		}
		return -1;
	}

	/** Decodes an ARM64 logical immediate when it's a plain contiguous run of ones (e.g. 7, 0xff). */
	private static int decodeLogicalImm(int w) {
		int n = (w >>> 22) & 1;
		int immr = (w >>> 16) & 0x3F;
		int imms = (w >>> 10) & 0x3F;
		if (n != 0 || immr != 0) {
			return -1;
		}
		int ones = imms + 1;
		if (ones >= 31) {
			return -1;
		}
		return (1 << ones) - 1;
	}

	// ------------------------------------------------------------------ shared

	private void dataRef(TriageResult r, FuncInfo f, long tgt, int len) {
		MemoryReader mr = m.reader();
		if (!mr.isMapped(tgt)) {
			return;
		}
		if (mr.isExecutable(tgt)) {
			int callee = r.funcAtEntry(tgt);
			if (callee >= 0) {
				r.addFuncRef(f.index, callee);
			}
			return;
		}
		// funcval: a rodata word holding a function entry (closure / go statement / callback)
		if (len < 0) {
			try {
				long p = m.ptr(tgt);
				int callee = r.funcAtEntry(p);
				if (callee >= 0) {
					r.addFuncRef(f.index, callee);
					return;
				}
			}
			catch (Mem.MemException e) {
				// fall through
			}
		}
		r.addDataRef(f.index, tgt, len);
	}
}
