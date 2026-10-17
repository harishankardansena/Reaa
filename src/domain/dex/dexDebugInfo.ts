/**
 * Decode a DEX `debug_info_item` (Dalvik Executable format) — the state machine
 * that encodes a method's source positions (line numbers) and local-variable
 * scopes, plus its parameter names. This is the DEX analogue of the JVM
 * LineNumberTable / LocalVariableTable, but it is an event stream, not a table.
 *
 * Facts are preserved on partial failure: a stream that runs short, drives a
 * line non-positive, or closes/restarts an empty register is marked `malformed`
 * while keeping every position and local recovered before the fault. Names are
 * left as string-pool indices here (`-1` = NO_INDEX); resolution is layered on
 * top. Addresses are 16-bit code units, bounded by the method's `insns_size`.
 */
import { DexCursor } from "./dexFile.js";

const DBG_END_SEQUENCE = 0x00;
const DBG_ADVANCE_PC = 0x01;
const DBG_ADVANCE_LINE = 0x02;
const DBG_START_LOCAL = 0x03;
const DBG_START_LOCAL_EXTENDED = 0x04;
const DBG_END_LOCAL = 0x05;
const DBG_RESTART_LOCAL = 0x06;
const DBG_SET_PROLOGUE_END = 0x07;
const DBG_SET_EPILOGUE_BEGIN = 0x08;
const DBG_SET_FILE = 0x09;
const DBG_FIRST_SPECIAL = 0x0a;
const DBG_LINE_BASE = -4;
const DBG_LINE_RANGE = 15;

/** Sentinel `nameIdx` for the implicit `this` local: it has no string-pool entry. */
export const DEX_THIS_NAME = -2;

/** `ACC_STATIC`: a static method has no implicit `this` parameter local. */
const ACC_STATIC = 0x8;

/**
 * The implicit parameter locals a debug_info_item starts at address 0: a method's
 * incoming parameters (and `this` for an instance method), seeded before the
 * opcode walk so that DBG_END_LOCAL / DBG_RESTART on a parameter register is
 * valid, not a fault. Register layout and types come from the code_item and the
 * proto; names come from the stream's `parameter_names`.
 */
export interface DexParameterLayout {
  /** `registers_size - ins_size`: the first register holding an incoming parameter. */
  readonly firstRegister: number;
  /**
   * The method's `registers_size`. A local naming a register at or past it is
   * malformed (DEX format), which also bounds the live-register maps.
   */
  readonly registersSize?: number;
  readonly accessFlags: number;
  /** The declaring class's type index, for the implicit `this`. */
  readonly thisTypeIdx: number;
  /** `null` when the method's proto cannot be resolved (count unknown). */
  readonly paramTypes: DexParameterList | null;
}

/**
 * A proto's parameters in declaration order: type index and whether each is
 * wide (long/double, two registers). Two typed arrays rather than one object
 * per parameter, so a 255-parameter proto costs two small allocations.
 */
export interface DexParameterList {
  readonly typeIdx: Uint16Array;
  readonly wide: Uint8Array;
}

/** Incoming argument words the parameters occupy (wide ones take two). */
export const dexParameterWords = (params: DexParameterList): number => {
  let words = 0;
  for (const wide of params.wide) words += wide === 1 ? 2 : 1;
  return words;
};

/** A local-variable scope. Name/type/signature are string-pool indices (`-1` = none). */
export interface DexLocalEntry {
  readonly register: number;
  readonly nameIdx: number;
  readonly typeIdx: number;
  readonly signatureIdx: number;
  readonly startAddress: number;
  readonly endAddress: number;
  /** The scope lies outside `[0, insns_size)` in code units. */
  readonly outOfRange: boolean;
}

/** The decoded debug info for one method. */
export interface DexMethodDebug {
  readonly present: boolean;
  readonly malformed: boolean;
  readonly lineStart: number;
  /** Parameter name indices in declaration order (`-1` = unnamed/stripped). */
  readonly parameterNames: readonly number[];
  /** Decoded locals; empty unless the caller asked to collect them. */
  readonly locals: readonly DexLocalEntry[];
  /**
   * Positions decoded inside the method's code (address < insns_size). A
   * shared stream (R8) can run past the code; those positions belong to no
   * instruction of this method and are not counted.
   */
  readonly positionCount: number;
  /** Locals decoded (including implicit `this`/parameters), collected or not. */
  readonly localCount: number;
  /**
   * Locals the stream itself declares (DBG_START_LOCAL[_EXTENDED]) whose scope
   * covers at least one instruction of the method, excluding the implicit
   * `this`/parameter locals seeded from the method's layout — the evidence that
   * local-variable debug info survived. Always at most `localCount`.
   */
  readonly explicitLocalCount: number;
  /** Collection stopped because the caller's `maxLocals` was exceeded. */
  readonly localLimitExceeded: boolean;
  readonly setFileEvents: number;
}

/**
 * What to materialise. Counting is always exact; positions are only counted
 * and locals are collected on request, so a summary allocates nothing per
 * position or local, and a detail view can cap the locals it will hold.
 */
export interface DexDecodeOptions {
  readonly budget?: DexWorkBudget;
  readonly collectLocals?: boolean;
  readonly maxLocals?: number;
}

/** A method with no `debug_info_item` (debug_info_off == 0). */
export const absentMethodDebug = (): DexMethodDebug => ({
  present: false,
  malformed: false,
  lineStart: 0,
  parameterNames: [],
  locals: [],
  positionCount: 0,
  localCount: 0,
  explicitLocalCount: 0,
  localLimitExceeded: false,
  setFileEvents: 0,
});

interface LiveLocal {
  readonly nameIdx: number;
  readonly typeIdx: number;
  readonly signatureIdx: number;
  readonly startAddress: number;
  /**
   * The DBG_START_LOCAL* event that declared it (shared by its restarts), or
   * null for an implicit `this`/parameter local seeded from the layout.
   */
  readonly declaration: { counted: boolean } | null;
}

/**
 * A Dalvik method's arguments occupy at most 255 registers (invoke/range carries
 * an 8-bit argument count), so a debug header declaring more parameter names is
 * malformed — rejected before allocating, not after.
 */
export const DEX_MAX_PARAMETERS = 255;

/** `true` keeps the walk going; `false` records a fault and stops it. */
type Step = boolean;

/**
 * Work units (debug opcodes, parameter-name reads, class_data entries) a caller
 * allows for one DEX member, shared and decremented across all of its methods.
 * The per-method guard bounds one stream; this bounds the member, so many
 * methods cannot multiply it.
 */
export interface DexWorkBudget {
  remaining: number;
  readonly limit: number;
}

export const dexWorkBudget = (limit: number): DexWorkBudget => ({
  remaining: limit,
  limit,
});

/** Charge one unit to `budget`; `false` once it is spent. */
export const chargeWork = (budget: DexWorkBudget): boolean => {
  if (budget.remaining <= 0) return false;
  budget.remaining -= 1;
  return true;
};

/** Mutable walk over one `debug_info_item`; one handler per opcode group. */
class DebugInfoWalk {
  private readonly cursor: DexCursor;
  private readonly locals: DexLocalEntry[] = [];
  private readonly live = new Map<number, LiveLocal>();
  private readonly lastByRegister = new Map<number, LiveLocal>();
  private readonly parameterNames: number[] = [];
  private line = 0;
  private lineStart = 0;
  private address = 0;
  private setFileEvents = 0;
  private malformed = false;
  private positionCount = 0;
  private localCount = 0;
  private explicitLocalCount = 0;
  private localLimitExceeded = false;
  private readonly budget: DexWorkBudget | undefined;
  private readonly collectLocals: boolean;
  private readonly maxLocals: number;

  constructor(
    bytes: Uint8Array,
    offset: number,
    private readonly insnsSize: number,
    private readonly layout: DexParameterLayout | undefined,
    options: DexDecodeOptions,
  ) {
    this.cursor = new DexCursor(bytes, offset);
    this.budget = options.budget;
    this.collectLocals = options.collectLocals ?? true;
    this.maxLocals = options.maxLocals ?? Number.POSITIVE_INFINITY;
  }

  /** Charge one unit of the member's work; false once the budget is spent. */
  private charge(): boolean {
    if (this.budget === undefined) return true;
    if (this.budget.remaining <= 0) return false;
    this.budget.remaining -= 1;
    return true;
  }

  /** Seed the implicit parameter locals (and `this`) live at address 0. */
  private seedParameters(): void {
    const layout = this.layout;
    if (layout === undefined) return;
    let register = Math.max(0, layout.firstRegister);
    const open = (reg: number, nameIdx: number, typeIdx: number): void => {
      const local: LiveLocal = {
        nameIdx,
        typeIdx,
        signatureIdx: -1,
        startAddress: 0,
        declaration: null,
      };
      this.live.set(reg, local);
      this.lastByRegister.set(reg, local);
    };
    if ((layout.accessFlags & ACC_STATIC) === 0) {
      open(register, DEX_THIS_NAME, layout.thisTypeIdx);
      register += 1;
    }
    const params = layout.paramTypes;
    const count = params?.typeIdx.length ?? 0;
    for (let i = 0; i < count; i += 1) {
      open(register, this.parameterNames[i] ?? -1, params!.typeIdx[i]!);
      register += params!.wide[i] === 1 ? 2 : 1;
    }
  }

  private pushLocal(register: number, local: LiveLocal, end: number): void {
    // A zero-length scope (e.g. kotlinc re-declaring a generic parameter at
    // address 0) covers no instruction; dexdump/ART skip it, and so do we.
    if (end <= local.startAddress) return;
    this.localCount += 1;
    // A declaration is evidence only once one of its scopes covers an
    // instruction of this method, so explicit locals stay a subset of locals.
    if (
      local.declaration !== null &&
      !local.declaration.counted &&
      local.startAddress < this.insnsSize
    ) {
      local.declaration.counted = true;
      this.explicitLocalCount += 1;
    }
    if (!this.collectLocals) return;
    if (this.locals.length >= this.maxLocals) {
      this.localLimitExceeded = true;
      return;
    }
    this.locals.push({
      register,
      nameIdx: local.nameIdx,
      typeIdx: local.typeIdx,
      signatureIdx: local.signatureIdx,
      startAddress: local.startAddress,
      endAddress: end,
      outOfRange: local.startAddress >= this.insnsSize || end > this.insnsSize,
    });
  }

  private header(): Step {
    const lineStart = this.cursor.uleb128();
    if (!lineStart.ok) return false;
    this.line = lineStart.value;
    this.lineStart = lineStart.value;
    const paramsSize = this.cursor.uleb128();
    if (!paramsSize.ok || paramsSize.value > DEX_MAX_PARAMETERS) return false;
    // ART decodes one name per proto parameter: fewer is an error there, and
    // more would leave names to be misread as opcodes. Either is malformed.
    const declared = this.layout?.paramTypes;
    if (
      declared !== undefined &&
      declared !== null &&
      paramsSize.value !== declared.typeIdx.length
    )
      return false;
    for (let i = 0; i < paramsSize.value; i += 1) {
      if (!this.charge()) return false;
      const nameIdx = this.cursor.uleb128p1();
      if (!nameIdx.ok) return false;
      this.parameterNames.push(nameIdx.value);
    }
    this.seedParameters();
    return true;
  }

  private startLocal(extended: boolean): Step {
    const reg = this.cursor.uleb128();
    const nameIdx = this.cursor.uleb128p1();
    const typeIdx = this.cursor.uleb128p1();
    let signatureIdx = -1;
    if (extended) {
      const sig = this.cursor.uleb128p1();
      if (!sig.ok) return false;
      signatureIdx = sig.value;
    }
    if (!reg.ok || !nameIdx.ok || !typeIdx.ok) return false;
    // A register past the method's frame is malformed; refusing it also caps
    // the live-register maps at registers_size (<= 65,535).
    const registersSize = this.layout?.registersSize;
    if (registersSize !== undefined && reg.value >= registersSize) return false;
    const existing = this.live.get(reg.value);
    if (existing) this.pushLocal(reg.value, existing, this.address); // implicit end
    const local: LiveLocal = {
      nameIdx: nameIdx.value,
      typeIdx: typeIdx.value,
      signatureIdx,
      startAddress: this.address,
      declaration: { counted: false },
    };
    this.live.set(reg.value, local);
    this.lastByRegister.set(reg.value, local);
    return true;
  }

  private endLocal(): Step {
    const reg = this.cursor.uleb128();
    if (!reg.ok) return false;
    const existing = this.live.get(reg.value);
    if (!existing) return false; // end of an empty register
    this.pushLocal(reg.value, existing, this.address);
    this.live.delete(reg.value);
    return true;
  }

  private restartLocal(): Step {
    const reg = this.cursor.uleb128();
    if (!reg.ok) return false;
    const previous = this.lastByRegister.get(reg.value);
    if (this.live.has(reg.value) || previous === undefined) return false;
    const local: LiveLocal = { ...previous, startAddress: this.address };
    this.live.set(reg.value, local);
    this.lastByRegister.set(reg.value, local);
    return true;
  }

  private setFile(): Step {
    const nameIdx = this.cursor.uleb128p1();
    if (!nameIdx.ok) return false;
    this.setFileEvents += 1;
    return true;
  }

  private special(op: number): void {
    const adjusted = op - DBG_FIRST_SPECIAL;
    this.line += DBG_LINE_BASE + (adjusted % DBG_LINE_RANGE);
    this.address += Math.floor(adjusted / DBG_LINE_RANGE);
    // d8 legitimately emits line 0 for synthetic methods; only a negative line
    // is structurally impossible (checked for every emitted row).
    if (this.line < 0) this.malformed = true;
    // Past the method's code (R8 shares streams across methods): no
    // instruction of this method maps to it.
    if (this.address >= this.insnsSize) return;
    this.positionCount += 1;
  }

  /** Dispatch one non-terminal opcode; returns false to stop on a fault. */
  private dispatch(op: number): Step {
    if (op === DBG_ADVANCE_PC) {
      const d = this.cursor.uleb128();
      if (!d.ok) return false;
      this.address += d.value;
      return true;
    }
    if (op === DBG_ADVANCE_LINE) {
      const d = this.cursor.sleb128();
      if (!d.ok) return false;
      this.line += d.value;
      return true;
    }
    if (op === DBG_START_LOCAL) return this.startLocal(false);
    if (op === DBG_START_LOCAL_EXTENDED) return this.startLocal(true);
    if (op === DBG_END_LOCAL) return this.endLocal();
    if (op === DBG_RESTART_LOCAL) return this.restartLocal();
    if (op === DBG_SET_FILE) return this.setFile();
    if (op === DBG_SET_PROLOGUE_END || op === DBG_SET_EPILOGUE_BEGIN)
      return true;
    this.special(op);
    return true;
  }

  private result(malformed: boolean): DexMethodDebug {
    return {
      present: true,
      malformed,
      lineStart: this.lineStart,
      parameterNames: this.parameterNames,
      locals: this.locals,
      positionCount: this.positionCount,
      localCount: this.localCount,
      explicitLocalCount: this.explicitLocalCount,
      localLimitExceeded: this.localLimitExceeded,
      setFileEvents: this.setFileEvents,
    };
  }

  private closeLiveAtEnd(): void {
    for (const [reg, local] of this.live)
      this.pushLocal(reg, local, this.insnsSize);
    this.live.clear();
  }

  run(): DexMethodDebug {
    if (!this.header()) return this.result(true);
    for (let guard = 0; guard < 2_000_000; guard += 1) {
      // Out of the member's work: stop; the caller sees remaining <= 0 and refuses.
      if (!this.charge() || this.localLimitExceeded) break;
      const op = this.cursor.u1();
      if (!op.ok) break;
      if (op.value === DBG_END_SEQUENCE) {
        this.closeLiveAtEnd();
        return this.result(this.malformed);
      }
      if (!this.dispatch(op.value)) break;
    }
    // Ran off the end without DBG_END_SEQUENCE, or a fault above.
    this.closeLiveAtEnd();
    return this.result(true);
  }
}

/**
 * Walk the `debug_info_item` at `offset`. `insnsSize` (code units) bounds local
 * scopes and flags out-of-range entries. Never throws; a structural or semantic
 * fault sets `malformed` and stops, preserving what was recovered.
 */
export const decodeDebugInfo = (
  bytes: Uint8Array,
  offset: number,
  insnsSize: number,
  layout?: DexParameterLayout,
  options: DexDecodeOptions = {},
): DexMethodDebug => {
  if (offset <= 0 || offset >= bytes.length)
    return { ...absentMethodDebug(), present: true, malformed: true };
  return new DebugInfoWalk(bytes, offset, insnsSize, layout, options).run();
};
