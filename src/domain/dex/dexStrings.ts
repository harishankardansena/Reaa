/**
 * Resolve names and type descriptors from a DEX file's string and type id pools
 * (Dalvik Executable format). A `string_id_item` is a u4 offset to a
 * `string_data_item` (`uleb128 utf16_size` then NUL-terminated modified UTF-8);
 * a `type_id_item` is a u4 index into the string pool. All lookups are bounded
 * and return `null` for an out-of-range index (including NO_INDEX = -1) or a
 * malformed/uncross-checked string, never a throw or a guess.
 */
import {
  decodeModifiedUtf8,
  modifiedUtf8JsonBound,
  modifiedUtf8Units,
} from "../modifiedUtf8.js";
import { DEX_MAX_PARAMETERS, type DexParameterList } from "./dexDebugInfo.js";
import { DEX_NO_INDEX, DexCursor, type DexHeader } from "./dexFile.js";

/**
 * Entries kept per memo. Memoisation is an optimisation, not a working set:
 * past the cap a value is recomputed, never retained, so a DEX with millions of
 * distinct strings or protos cannot grow these maps without bound.
 */
const MEMO_LIMIT = 65_536;

/** Decoded UTF-16 code units retained across the string memo. */
const RETAINED_CHARS_LIMIT = 4 * 1024 * 1024;

/** Proto parameter entries retained across the proto memo (each up to 255). */
const RETAINED_PARAMS_LIMIT = 1024 * 1024;

/**
 * Charges `units` of work (bytes scanned or decoded) to the caller's budget.
 * The resolver never refuses on its own; the caller checks its budget and
 * refuses the whole call once it is spent.
 */
export type DexStringCharge = (units: number) => void;

interface RawString {
  readonly dataOffset: number;
  readonly bytes: Uint8Array;
  readonly utf16Size: number;
}

/**
 * The resolver is the owner of string identity for one DEX file. Strings are
 * memoised by their `string_data` offset, so many ids aliasing one long string
 * share a single decoded copy; retained decoded text is capped; and every scan
 * and decode is charged to the caller's work budget.
 */
export class DexStringResolver {
  private readonly view: DataView;
  readonly #strings = new Map<number, string | null>();
  readonly #bounds = new Map<number, number>();
  #retainedChars = 0;
  #retainedParams = 0;
  constructor(
    private readonly bytes: Uint8Array,
    private readonly header: DexHeader,
    private readonly charge: DexStringCharge = () => undefined,
    /** True once the caller's budget is spent: no new scan or decode starts. */
    private readonly spent: () => boolean = () => false,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  #remember<K, V>(memo: Map<K, V>, key: K, value: V): void {
    if (memo.size < MEMO_LIMIT) memo.set(key, value);
  }

  /** Resolve a string-pool index to its text, or `null` when absent/malformed. */
  string(index: number): string | null {
    const raw = this.#raw(index);
    if (raw === null) return null;
    const cached = this.#strings.get(raw.dataOffset);
    if (cached !== undefined || this.#strings.has(raw.dataOffset))
      return cached ?? null;
    if (this.spent()) return null;
    this.charge(raw.bytes.length);
    const decoded = this.#decode(raw);
    const size = decoded?.length ?? 0;
    if (this.#retainedChars + size <= RETAINED_CHARS_LIMIT) {
      this.#retainedChars += size;
      this.#remember(this.#strings, raw.dataOffset, decoded);
    }
    return decoded;
  }

  /**
   * Whether `string(index)` would resolve to a string, checked without
   * allocating the decoded text (charged like a decode).
   */
  isValid(index: number): boolean {
    const raw = this.#raw(index);
    if (raw === null) return false;
    if (this.#strings.has(raw.dataOffset))
      return this.#strings.get(raw.dataOffset) !== null;
    this.charge(raw.bytes.length);
    return modifiedUtf8Units(raw.bytes) === raw.utf16Size;
  }

  /**
   * Upper bound on the JSON bytes `string(index)` serialises to (4 for `null`),
   * computed from the raw bytes without decoding and memoised per index.
   */
  jsonBound(index: number): number {
    const raw = this.#raw(index);
    if (raw === null) return 4;
    let bound = this.#bounds.get(raw.dataOffset);
    if (bound === undefined) {
      this.charge(raw.bytes.length);
      bound = Math.max(4, modifiedUtf8JsonBound(raw.bytes));
      this.#remember(this.#bounds, raw.dataOffset, bound);
    }
    return bound;
  }

  /** JSON bound of a type id's descriptor string. */
  typeJsonBound(index: number): number {
    const stringIdx = this.#typeStringIndex(index);
    return stringIdx === null ? 4 : this.jsonBound(stringIdx);
  }

  #decode(raw: {
    readonly bytes: Uint8Array;
    readonly utf16Size: number;
  }): string | null {
    const decoded = decodeModifiedUtf8(raw.bytes);
    // A length that disagrees with the declared UTF-16 size is malformed.
    return decoded === null || decoded.length !== raw.utf16Size
      ? null
      : decoded;
  }

  /** The string's modified-UTF8 bytes (a view) and declared UTF-16 size, memoised. */
  #raw(index: number): RawString | null {
    const memo = this.#rawMemo.get(index);
    if (memo !== undefined || this.#rawMemo.has(index)) return memo ?? null;
    const raw = this.#locate(index);
    this.#remember(this.#rawMemo, index, raw);
    return raw;
  }

  readonly #rawMemo = new Map<number, RawString | null>();

  #locate(index: number): RawString | null {
    // A spent budget means the caller will refuse the whole call; starting
    // another (possibly member-sized) scan would only waste the time.
    if (this.spent()) return null;
    if (
      index < 0 ||
      index === DEX_NO_INDEX ||
      index >= this.header.stringIdsSize
    )
      return null;
    const idOffset = this.header.stringIdsOff + index * 4;
    if (idOffset + 4 > this.bytes.length) return null;
    const dataOffset = this.view.getUint32(idOffset, true);
    if (dataOffset <= 0 || dataOffset >= this.bytes.length) return null;
    const cursor = new DexCursor(this.bytes, dataOffset);
    const utf16Size = cursor.uleb128();
    if (!utf16Size.ok) return null;
    // Modified UTF-8 runs to a NUL terminator; find it within the buffer.
    let end = cursor.offset;
    while (end < this.bytes.length && this.bytes[end] !== 0x00) end += 1;
    this.charge(end - cursor.offset);
    if (end >= this.bytes.length) return null; // unterminated
    return {
      dataOffset,
      bytes: this.bytes.subarray(cursor.offset, end),
      utf16Size: utf16Size.value,
    };
  }

  /**
   * Compare a type's descriptor with `wanted` (modified-UTF-8 bytes) without
   * decoding it: `unreadable` when the descriptor cannot be located or is not
   * valid modified UTF-8 of its declared length.
   */
  typeIdentity(
    index: number,
    wanted: Uint8Array,
  ): "match" | "different" | "unreadable" {
    const stringIdx = this.#typeStringIndex(index);
    const raw = stringIdx === null ? null : this.#raw(stringIdx);
    if (raw === null) return "unreadable";
    // An undecodable descriptor is an unknown identity, never "different":
    // validated (charged, allocation-free) before any comparison.
    this.charge(raw.bytes.length);
    if (modifiedUtf8Units(raw.bytes) !== raw.utf16Size) return "unreadable";
    if (raw.bytes.length !== wanted.length) return "different";
    for (let i = 0; i < wanted.length; i++)
      if (raw.bytes[i] !== wanted[i]) return "different";
    return "match";
  }

  /** Resolve a type-pool index to its descriptor string (e.g. `Lcom/example/Foo;`). */
  typeDescriptor(index: number): string | null {
    const stringIdx = this.#typeStringIndex(index);
    return stringIdx === null ? null : this.string(stringIdx);
  }

  #typeStringIndex(index: number): number | null {
    if (index < 0 || index === DEX_NO_INDEX || index >= this.header.typeIdsSize)
      return null;
    const idOffset = this.header.typeIdsOff + index * 4;
    if (idOffset + 4 > this.bytes.length) return null;
    return this.view.getUint32(idOffset, true);
  }

  /** Bounded u4 read, or null past the end. */
  #u4(at: number): number | null {
    return at >= 0 && at + 4 <= this.bytes.length
      ? this.view.getUint32(at, true)
      : null;
  }

  /** A method's `proto_idx`, or null when the method or proto is out of range. */
  methodProtoIndex(methodIndex: number): number | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    const protoAt = this.header.methodIdsOff + methodIndex * 8 + 2;
    if (protoAt + 2 > this.bytes.length) return null;
    const protoIndex = this.view.getUint16(protoAt, true);
    return protoIndex < this.header.protoIdsSize ? protoIndex : null;
  }

  /** `method_id_item` = { class_idx u2, proto_idx u2, name_idx u4 }. */
  methodName(methodIndex: number): string | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    const nameIdx = this.#u4(this.header.methodIdsOff + methodIndex * 8 + 4);
    return nameIdx === null ? null : this.string(nameIdx);
  }

  /**
   * The JVM-form descriptor of a method, e.g. `(Ljava/lang/String;I)V`, built
   * from its `proto_id_item` { shorty_idx u4, return_type_idx u4,
   * parameters_off u4 } and the `type_list` at `parameters_off`.
   */
  /**
   * Upper bound on the JSON bytes of `methodDescriptor(methodIndex)` (and of
   * `methodName`), computed from the proto's type ids and memoised string
   * bounds without building the descriptor, so a caller can refuse before a
   * proto repeating one long type up to 255 times is joined.
   */
  methodJsonBound(methodIndex: number): number {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize) return 8;
    const nameIdx = this.#u4(this.header.methodIdsOff + methodIndex * 8 + 4);
    const nameBound = nameIdx === null ? 4 : this.jsonBound(nameIdx);
    const protoIndex = this.methodProtoIndex(methodIndex);
    if (protoIndex === null) return nameBound + 4;
    const protoBase = this.header.protoIdsOff + protoIndex * 12;
    const returnTypeIdx = this.#u4(protoBase + 4);
    const parametersOff = this.#u4(protoBase + 8);
    if (returnTypeIdx === null || parametersOff === null) return nameBound + 4;
    let total = nameBound + 4 + this.typeJsonBound(returnTypeIdx);
    if (parametersOff === 0) return total;
    const size = this.#u4(parametersOff);
    if (size === null || size > DEX_MAX_PARAMETERS) return total;
    for (let i = 0; i < size; i += 1) {
      const at = parametersOff + 4 + i * 2;
      if (at + 2 > this.bytes.length) break;
      total += this.typeJsonBound(this.view.getUint16(at, true));
    }
    return total;
  }

  methodDescriptor(methodIndex: number): string | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    // method_id_item: class_idx u2 @0, proto_idx u2 @2, name_idx u4 @4.
    const protoAt = this.header.methodIdsOff + methodIndex * 8 + 2;
    if (protoAt + 2 > this.bytes.length) return null;
    const protoIndex = this.view.getUint16(protoAt, true);
    if (protoIndex >= this.header.protoIdsSize) return null;
    const protoBase = this.header.protoIdsOff + protoIndex * 12;
    const returnTypeIdx = this.#u4(protoBase + 4);
    const parametersOff = this.#u4(protoBase + 8);
    if (returnTypeIdx === null || parametersOff === null) return null;
    const returnDescriptor = this.typeDescriptor(returnTypeIdx);
    if (returnDescriptor === null) return null;
    const params = this.#typeList(parametersOff);
    if (params === null) return null;
    return `(${params.join("")})${returnDescriptor}`;
  }

  /**
   * A method's proto parameter types, in declaration order, each with whether it
   * is wide (long/double — occupies two registers but one parameter slot). Used
   * to seed the implicit parameter locals that a debug_info_item starts at
   * address 0. Returns null when the method or proto cannot be resolved.
   */
  methodParameters(methodIndex: number): DexParameterList | null {
    if (methodIndex < 0 || methodIndex >= this.header.methodIdsSize)
      return null;
    const protoAt = this.header.methodIdsOff + methodIndex * 8 + 2;
    if (protoAt + 2 > this.bytes.length) return null;
    const protoIndex = this.view.getUint16(protoAt, true);
    if (protoIndex >= this.header.protoIdsSize) return null;
    const parametersOff = this.#u4(
      this.header.protoIdsOff + protoIndex * 12 + 8,
    );
    if (parametersOff === null) return null;
    // Keyed by the type_list itself: protos (and so methods) sharing a
    // parameter list decode it once, so total work follows the type_list
    // bytes present in the file rather than methods x parameters.
    const cached = this.#protoParams.get(parametersOff);
    if (cached !== undefined || this.#protoParams.has(parametersOff))
      return cached ?? null;
    const params = this.#typeListParameters(parametersOff);
    const size = params?.typeIdx.length ?? 0;
    this.charge(size + 1);
    // Bounded by retained parameter entries, not just lists: one list can
    // expand to 255 entries.
    if (this.#retainedParams + size <= RETAINED_PARAMS_LIMIT) {
      this.#retainedParams += size;
      this.#remember(this.#protoParams, parametersOff, params);
    }
    return params;
  }

  readonly #protoParams = new Map<number, DexParameterList | null>();

  #typeListParameters(parametersOff: number): DexParameterList | null {
    if (parametersOff === 0)
      return { typeIdx: new Uint16Array(0), wide: new Uint8Array(0) };
    const size = this.#u4(parametersOff);
    // A proto with more parameters than a method's 255 argument registers can
    // hold is malformed; refuse before allocating its list.
    if (size === null || size > DEX_MAX_PARAMETERS) return null;
    if (parametersOff + 4 + size * 2 > this.bytes.length) return null;
    const typeIdx = new Uint16Array(size);
    const wide = new Uint8Array(size);
    for (let i = 0; i < size; i += 1) {
      typeIdx[i] = this.view.getUint16(parametersOff + 4 + i * 2, true);
      wide[i] = this.#isWideType(typeIdx[i]!) ? 1 : 0;
    }
    return { typeIdx, wide };
  }

  /**
   * Whether a type is `J` or `D` (two registers), read from the raw descriptor
   * bytes: only the one-byte strings qualify, so no descriptor is decoded.
   */
  #isWideType(typeIdx: number): boolean {
    // Memoised per type id (0 unknown, 1 narrow, 2 wide): type ids are 16-bit
    // here, so 64 KiB answers every repeat without a map lookup or rescan.
    const known = this.#wideByType[typeIdx];
    if (known !== undefined && known !== 0) return known === 2;
    const wide = this.#resolveWide(typeIdx);
    if (typeIdx < this.#wideByType.length)
      this.#wideByType[typeIdx] = wide ? 2 : 1;
    return wide;
  }

  readonly #wideByType = new Uint8Array(0x10000);

  #resolveWide(typeIdx: number): boolean {
    const stringIdx = this.#typeStringIndex(typeIdx);
    const raw = stringIdx === null ? null : this.#raw(stringIdx);
    if (raw === null || raw.utf16Size !== 1 || raw.bytes.length !== 1)
      return false;
    return raw.bytes[0] === 0x4a || raw.bytes[0] === 0x44; // 'J' | 'D'
  }

  /** A `type_list` { size u4, list[size] of u2 type_idx }, resolved to descriptors. */
  #typeList(offset: number): string[] | null {
    if (offset === 0) return []; // no parameters
    const size = this.#u4(offset);
    if (size === null || size > DEX_MAX_PARAMETERS) return null;
    const descriptors: string[] = [];
    for (let i = 0; i < size; i += 1) {
      const at = offset + 4 + i * 2;
      if (at + 2 > this.bytes.length) return null;
      const descriptor = this.typeDescriptor(this.view.getUint16(at, true));
      if (descriptor === null) return null;
      descriptors.push(descriptor);
    }
    return descriptors;
  }
}
