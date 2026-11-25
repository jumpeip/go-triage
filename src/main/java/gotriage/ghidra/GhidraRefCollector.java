package gotriage.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import gotriage.core.Progress;
import gotriage.core.RefCollector;
import gotriage.core.TriageResult;

/**
 * Uses the references Ghidra's analysis already created (calls, jumps, data reads). Works on
 * every processor Ghidra supports and resolves references the byte scanner can't see. String
 * lengths come from a small scalar operand in the next few instructions, as Go passes strings
 * as (pointer, length) pairs.
 */
public final class GhidraRefCollector implements RefCollector {

	private final Program program;
	private int refsSeen;

	public GhidraRefCollector(Program program) {
		this.program = program;
	}

	@Override
	public String name() {
		return "Ghidra references";
	}

	public int refsSeen() {
		return refsSeen;
	}

	@Override
	public void collect(TriageResult r, Progress p) {
		ReferenceManager rm = program.getReferenceManager();
		Listing listing = program.getListing();
		AddressSet exec = new AddressSet();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (b.isExecute() && b.isInitialized()) {
				exec.add(b.getStart(), b.getEnd());
			}
		}
		AddressIterator it = rm.getReferenceSourceIterator(exec, true);
		long n = 0;
		long total = Math.max(1, exec.getNumAddresses());
		while (it.hasNext()) {
			Address from = it.next();
			if ((++n & 0xfff) == 0) {
				if (p.isCancelled()) {
					return;
				}
				p.update("Reading Ghidra references", from.subtract(exec.getMinAddress()), total);
			}
			int fi = r.funcContaining(from.getOffset());
			if (fi < 0) {
				continue;
			}
			for (Reference ref : rm.getReferencesFrom(from)) {
				Address to = ref.getToAddress();
				if (!to.isMemoryAddress()) {
					continue;
				}
				refsSeen++;
				RefType t = ref.getReferenceType();
				long target = to.getOffset();
				if (t.isCall() || t.isJump()) {
					int callee = r.funcAtEntry(target);
					if (callee >= 0 && callee != fi) {
						r.addCall(fi, callee);
					}
				}
				else if (t.isData() || t.isRead() || t.isIndirect()) {
					int callee = r.funcAtEntry(target);
					if (callee >= 0) {
						r.addFuncRef(fi, callee);
						continue;
					}
					if (t.isRead() && !t.isData()) {
						r.addDataRef(fi, target, -2);
						continue;
					}
					r.addDataRef(fi, target, lengthAfter(listing, from));
				}
			}
		}
	}

	/** Small scalar operand in the next few instructions (the Go string length), or -1. */
	private static int lengthAfter(Listing listing, Address from) {
		Instruction ins = listing.getInstructionAt(from);
		if (ins == null) {
			return -1;
		}
		Instruction cur = ins.getNext();
		for (int k = 0; k < 4 && cur != null; k++) {
			if (cur.getFlowType().isCall()) {
				break;
			}
			for (int op = 0; op < cur.getNumOperands(); op++) {
				int ot = cur.getOperandType(op);
				// immediate operands only (not displacements inside memory operands)
				if (cur.getOperandReferences(op).length > 0 || !OperandType.isScalar(ot)
						|| OperandType.isDynamic(ot) || OperandType.isAddress(ot)) {
					continue;
				}
				for (Object o : cur.getOpObjects(op)) {
					if (o instanceof Scalar s) {
						long v = s.getUnsignedValue();
						if (v > 0 && v <= 0x20000) {
							return (int) v;
						}
					}
				}
			}
			cur = cur.getNext();
		}
		return -1;
	}
}
