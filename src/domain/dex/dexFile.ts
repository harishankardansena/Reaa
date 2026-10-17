/**
 * Dependency-free structural reader for Android DEX files (Dalvik Executable
 * format). Scope: frame the file — magic/version, the fixed header, the id-table
 * locations, each `class_def_item`, and, on demand, a class's `class_data_item`
 * and a method's `code_item` down to its `debug_info_off`. Interpretation of the
 * `debug_info_item` state machine and the string pool is layered on top of this
 * reader (see dexDebugInfo.ts / dexStrings.ts), not performed here.
 *
 * Every length- or offset-driven read is bounded against the buffer before use;
 * malformed or truncated input yields a tagged {@link DexFileParseError} via
 * {@link Result}, never a throw or an unchecked allocation. DEX is little-endian
 * (ART rejects reverse-endian too), so a reverse `endian_tag` is refused, not
 * byte-swapped. Addresses in DEX are 16-bit code units, not bytes.
 */
import { type Result, err, ok } from "../result.js";

/** The unversioned DEX magic prefix; the 3 following ASCII digits are the version. */
const DEX_MAGIC_PREFIX = [0x64, 0x65, 0x78, 0x0a] as const; // "dex\n"
const ENDIAN_CONSTANT = 0x12345678;
const REVERSE_ENDIAN_CONSTANT = 0x78563412;
const HEADER_SIZE_V40 = 0x70;

/** NO_INDEX sentinel for `source_file_idx` and other u4 index fields (DEX spec). */
export const DEX_NO_INDEX = 0xffffffff;

/**
 * Versions this reader decodes. 036 was withdrawn (libdexfile rejects it); 041
 * (Android 15+) introduces a wider container header and is refused for now;
 * compact dex (`cdex`) is a separate on-device format and is refused.
 */
const SUPPORTED_VERSIONS: ReadonlySet<string> = new Set([
  "035",
  "037",
  "038",
  "039",
  "040",
]);

/** Why framing failed. Offsets are byte positions into the supplied buffer. */
export type DexFileParseError =
  | { readonly kind: "bad-magic"; readonly offset: number }
  | { readonly kind: "compact-dex"; readonly offset: number }
  | { readonly kind: "reverse-endian"; readonly offset: number }
  | { readonly kind: "unsupported-version"; readonly version: string }
  | {
      readonly kind: "bad-header";
      readonly offset: number;
      readonly detail: string;
    }
  | {
      readonly kind: "truncated";
      readonly offset: number;
      readonly need: number;
      readonly have: number;
    }
  | {
      readonly kind: "budget-exceeded";
      readonly offset: number;
      readonly resource: "class-defs" | "class-data" | "leb128" | "work";
      readonly declared: number;
      readonly remaining: number;
    }
  /** A class_data entry names an index past the id table it indexes. */
  | {
      readonly kind: "member-index-exceeds-ids";
      readonly offset: number;
      readonly members: "fields" | "methods";
      readonly index: number;
      readonly bound: number;
    }
  | {
      readonly kind: "invalid-index";
      readonly offset: number;
      readonly index: number;
      readonly bound: number;
    };

/** Sequential, bounds-checked little-endian cursor with LEB128 support. */
export class DexCursor {
  offset: number;
  private readonly view: DataView;
  constructor(
    private readonly bytes: Uint8Array,
    start = 0,
  ) {
    this.offset = start;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private short(n: number): DexFileParseError | null {
    return this.remaining < n
      ? {
          kind: "truncated",
          offset: this.offset,
          need: n,
          have: this.remaining,
        }
      : null;
  }

  u1(): Result<number, DexFileParseError> {
    const s = this.short(1);
    if (s) return err(s);
    const v = this.bytes[this.offset]!;
    this.offset += 1;
    return ok(v);
  }

  u2(): Result<number, DexFileParseError> {
    const s = this.short(2);
    if (s) return err(s);
    const v = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return ok(v);
  }

  u4(): Result<number, DexFileParseError> {
    const s = this.short(4);
    if (s) return err(s);
    const v = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return ok(v);
  }

  /** Unsigned LEB128, capped at 5 bytes; a longer run is rejected rather than wrapped. */
  uleb128(): Result<number, DexFileParseError> {
    let result = 0;
    let shift = 0;
    for (let i = 0; i < 5; i += 1) {
      const b = this.u1();
      if (!b.ok) return b;
      result |= (b.value & 0x7f) << shift;
      if ((b.value & 0x80) === 0) return ok(result >>> 0);
      shift += 7;
    }
    return err({
      kind: "budget-exceeded",
      offset: this.offset,
      resource: "leb128",
      declared: 5,
      remaining: this.remaining,
    });
  }

  /** Signed LEB128, capped at 5 bytes, sign-extended from the final continuation. */
  sleb128(): Result<number, DexFileParseError> {
    let result = 0;
    let shift = 0;
    for (let i = 0; i < 5; i += 1) {
      const b = this.u1();
      if (!b.ok) return b;
      result |= (b.value & 0x7f) << shift;
      shift += 7;
      if ((b.value & 0x80) === 0) {
        if (shift < 32 && (b.value & 0x40) !== 0) result |= -(1 << shift);
        return ok(result);
      }
    }
    return err({
      kind: "budget-exceeded",
      offset: this.offset,
      resource: "leb128",
      declared: 5,
      remaining: this.remaining,
    });
  }

  /** `uleb128p1`: the encoded ULEB128 value minus one, so 0 encodes -1 (NO_INDEX). */
  uleb128p1(): Result<number, DexFileParseError> {
    const v = this.uleb128();
    return v.ok ? ok(v.value - 1) : v;
  }

  skip(n: number): Result<void, DexFileParseError> {
    const s = this.short(n);
    if (s) return err(s);
    this.offset += n;
    return ok(undefined);
  }
}

/** The fixed DEX header fields this reader needs to reach code and debug info. */
export interface DexHeader {
  readonly version: string;
  readonly fileSize: number;
  readonly stringIdsSize: number;
  readonly stringIdsOff: number;
  readonly typeIdsSize: number;
  readonly typeIdsOff: number;
  readonly protoIdsSize: number;
  readonly protoIdsOff: number;
  readonly fieldIdsSize: number;
  readonly methodIdsSize: number;
  readonly methodIdsOff: number;
  readonly classDefsSize: number;
  readonly classDefsOff: number;
  readonly dataSize: number;
  readonly dataOff: number;
}

/** A `class_def_item`: only the fields debug inspection needs are retained. */
export interface DexClassDef {
  readonly classIdx: number;
  readonly accessFlags: number;
  readonly superclassIdx: number;
  /** Index into the string pool, or {@link DEX_NO_INDEX} when absent. */
  readonly sourceFileIdx: number;
  /** Offset of the `class_data_item`, or 0 when the class has no members. */
  readonly classDataOff: number;
}

/** A framed DEX file: its header and every `class_def_item`. */
/**
 * A framed DEX file. `class_def_item`s are a fixed 32-byte table and are read
 * on demand with {@link readClassDef}, never materialised as millions of
 * objects; `header.classDefsSize` is their count (checked to fit the buffer).
 */
export interface DexFile {
  readonly header: DexHeader;
  /** The bytes the header frames: the first `file_size` bytes. */
  readonly framed: Uint8Array;
  /** Bytes after `file_size`, never read (ART 15+ ignores them). */
  readonly trailingBytes: number;
}

/** Read the `index`-th class_def_item (caller keeps `index < classDefsSize`). */
export const readClassDef = (
  bytes: Uint8Array,
  header: DexHeader,
  index: number,
): DexClassDef => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const base = header.classDefsOff + index * 32;
  return {
    classIdx: view.getUint32(base, true),
    accessFlags: view.getUint32(base + 4, true),
    superclassIdx: view.getUint32(base + 8, true),
    sourceFileIdx: view.getUint32(base + 16, true),
    classDataOff: view.getUint32(base + 24, true),
  };
};

/** One method within a `class_data_item` (indices resolved from their deltas). */
export interface DexEncodedMethod {
  readonly methodIdx: number;
  readonly accessFlags: number;
  /** Offset of the `code_item`, or 0 for abstract/native methods. */
  readonly codeOff: number;
}

/** The decoded members of a `class_data_item` relevant to debug inspection. */
/** The `code_item` header, down to the fields needed to reach its debug info. */
export interface DexCodeItem {
  readonly registersSize: number;
  readonly insSize: number;
  readonly outsSize: number;
  readonly triesSize: number;
  /** Offset of the `debug_info_item`, or 0 when the method carries none. */
  readonly debugInfoOff: number;
  /** Instruction count in 16-bit code units (not bytes). */
  readonly insnsSize: number;
}

const readVersion = (bytes: Uint8Array): string =>
  String.fromCharCode(bytes[4]!, bytes[5]!, bytes[6]!);

/** Frame a DEX file: validate the header, then read every `class_def_item`. */
export const parseDexFile = (
  bytes: Uint8Array,
): Result<DexFile, DexFileParseError> => {
  if (bytes.length < HEADER_SIZE_V40)
    return err({
      kind: "truncated",
      offset: 0,
      need: HEADER_SIZE_V40,
      have: bytes.length,
    });

  // Compact dex ("cdex") shares the first three bytes; distinguish before magic.
  if (bytes[0] === 0x63 && bytes[1] === 0x64 && bytes[2] === 0x65)
    return err({ kind: "compact-dex", offset: 0 });
  for (let i = 0; i < DEX_MAGIC_PREFIX.length; i += 1)
    if (bytes[i] !== DEX_MAGIC_PREFIX[i])
      return err({ kind: "bad-magic", offset: 0 });
  if (bytes[7] !== 0x00) return err({ kind: "bad-magic", offset: 7 });

  const version = readVersion(bytes);
  if (!SUPPORTED_VERSIONS.has(version))
    return err({ kind: "unsupported-version", version });

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const endian = view.getUint32(40, true);
  if (endian === REVERSE_ENDIAN_CONSTANT)
    return err({ kind: "reverse-endian", offset: 40 });
  if (endian !== ENDIAN_CONSTANT)
    return err({
      kind: "bad-header",
      offset: 40,
      detail: `endian_tag ${endian.toString(16)} is neither the standard nor reverse constant`,
    });

  const headerSize = view.getUint32(36, true);
  if (headerSize !== HEADER_SIZE_V40)
    return err({
      kind: "bad-header",
      offset: 36,
      detail: `header_size ${String(headerSize)} is not 0x70`,
    });

  const fileSize = view.getUint32(32, true);
  const header: DexHeader = {
    version,
    fileSize,
    stringIdsSize: view.getUint32(56, true),
    stringIdsOff: view.getUint32(60, true),
    typeIdsSize: view.getUint32(64, true),
    typeIdsOff: view.getUint32(68, true),
    protoIdsSize: view.getUint32(72, true),
    protoIdsOff: view.getUint32(76, true),
    fieldIdsSize: view.getUint32(80, true),
    methodIdsSize: view.getUint32(88, true),
    methodIdsOff: view.getUint32(92, true),
    classDefsSize: view.getUint32(96, true),
    classDefsOff: view.getUint32(100, true),
    dataSize: view.getUint32(104, true),
    dataOff: view.getUint32(108, true),
  };
  // ART frames a DEX on file_size: claiming more bytes than exist is
  // truncation, and trailing bytes past it are ignored by ART 15+ (rejected by
  // ART 14 and earlier). Every offset is checked against the framed bytes, so
  // nothing in the trailing bytes is ever read.
  if (fileSize < HEADER_SIZE_V40)
    return err({
      kind: "bad-header",
      offset: 32,
      detail: `file_size ${String(fileSize)} is smaller than the 0x70-byte header`,
    });
  if (fileSize > bytes.length)
    return err({
      kind: "bad-header",
      offset: 32,
      detail: `file_size ${String(fileSize)} exceeds the ${String(bytes.length)} bytes present (truncated DEX)`,
    });
  if (fileSize < bytes.length) {
    const framed = parseDexFile(bytes.subarray(0, fileSize));
    return framed.ok
      ? ok({ ...framed.value, trailingBytes: bytes.length - fileSize })
      : framed;
  }

  // Each class_def_item is a fixed 32 bytes; reject an impossible count up front.
  if (header.classDefsSize * 32 > bytes.length - header.classDefsOff)
    return err({
      kind: "budget-exceeded",
      offset: header.classDefsOff,
      resource: "class-defs",
      declared: header.classDefsSize,
      remaining: Math.max(0, bytes.length - header.classDefsOff),
    });

  return ok({ header, framed: bytes, trailingBytes: 0 });
};

/**
 * Charge one unit of caller-owned work; `false` once it is spent. Lets a
 * caller bound the total class_data parsing of a whole call, since many
 * class_defs may point at the same (or overlapping) class_data.
 */
export type DexWorkCharge = () => boolean;

const workSpentError = (cursor: DexCursor): DexFileParseError => ({
  kind: "budget-exceeded",
  offset: cursor.offset,
  resource: "work",
  declared: 0,
  remaining: cursor.remaining,
});

/** What one {@link DexClassDataReader.step} read. */
export type DexClassDataStep = "field" | "method" | "end" | "failed";

/**
 * Pull-driven reader over a `class_data_item`: each {@link step} reads one
 * encoded_field (skipped) or encoded_method, charged to the caller's work, so
 * a consumer can pause between entries and stop early. Nothing is
 * materialised while stepping; {@link method} builds the method last read.
 *
 * Counts are refused before any entry is read only when they cannot fit the
 * remaining bytes (two bytes per encoded_field, three per encoded_method).
 * They are not bounded by the id tables: ART's verifier (CheckOrder) rejects
 * only a decreasing index within a list, and a repeat across lists (an
 * instance field equal to a static one, a virtual method equal to a direct
 * one), so a list that repeats an index is valid and may be longer than the
 * id table. The caller's work charge and pacing bound the walk instead. As in
 * ART's CheckIndex, each entry's cumulative index must name an id; unsigned
 * deltas never decrease it.
 */
export class DexClassDataReader {
  readonly #fieldLists: number[];
  #fieldsLeft = 0;
  #fieldIdx = 0;
  readonly #methodLists: number[];
  #methodsLeft = 0;
  #methodIdx = 0;
  #accessFlags = 0;
  #codeOff = 0;
  #methodCount = 0;
  #failure: DexFileParseError | null = null;

  private constructor(
    private readonly cursor: DexCursor,
    private readonly ids: Pick<DexHeader, "fieldIdsSize" | "methodIdsSize">,
    counts: readonly [number, number, number, number],
  ) {
    this.#fieldLists = [counts[0], counts[1]];
    this.#methodLists = [counts[2], counts[3]];
  }

  static open(
    bytes: Uint8Array,
    offset: number,
    ids: Pick<DexHeader, "fieldIdsSize" | "methodIdsSize">,
  ): Result<DexClassDataReader, DexFileParseError> {
    if (offset <= 0 || offset >= bytes.length)
      return err({
        kind: "invalid-index",
        offset,
        index: offset,
        bound: bytes.length,
      });
    const cursor = new DexCursor(bytes, offset);
    const staticFields = cursor.uleb128();
    if (!staticFields.ok) return staticFields;
    const instanceFields = cursor.uleb128();
    if (!instanceFields.ok) return instanceFields;
    const directMethods = cursor.uleb128();
    if (!directMethods.ok) return directMethods;
    const virtualMethods = cursor.uleb128();
    if (!virtualMethods.ok) return virtualMethods;

    // encoded_field: field_idx_diff uleb + access uleb (at least two bytes).
    const fields = staticFields.value + instanceFields.value;
    if (fields > cursor.remaining / 2)
      return err({
        kind: "budget-exceeded",
        offset: cursor.offset,
        resource: "class-data",
        declared: fields,
        remaining: cursor.remaining,
      });
    return ok(
      new DexClassDataReader(cursor, ids, [
        staticFields.value,
        instanceFields.value,
        directMethods.value,
        virtualMethods.value,
      ]),
    );
  }

  /** Methods read so far. */
  get methodCount(): number {
    return this.#methodCount;
  }

  /** Why the last step returned `"failed"`. */
  get failure(): DexFileParseError | null {
    return this.#failure;
  }

  /** The method the last `"method"` step read (indices resolved from their deltas). */
  get method(): DexEncodedMethod {
    return {
      methodIdx: this.#methodIdx,
      accessFlags: this.#accessFlags,
      codeOff: this.#codeOff,
    };
  }

  /** Read the next entry: direct then virtual methods follow the fields. */
  step(charge: DexWorkCharge): DexClassDataStep {
    if (this.#failure !== null) return "failed";
    const cursor = this.cursor;
    while (this.#fieldsLeft === 0 && this.#fieldLists.length > 0) {
      this.#fieldsLeft = this.#fieldLists.shift() ?? 0;
      this.#fieldIdx = 0; // indices are cumulative deltas within each list
    }
    if (this.#fieldsLeft > 0) {
      if (!charge()) return this.#fail(workSpentError(cursor));
      const at = cursor.offset;
      const diff = cursor.uleb128();
      if (!diff.ok || !cursor.uleb128().ok)
        return this.#fail({
          kind: "truncated",
          offset: cursor.offset,
          need: 1,
          have: cursor.remaining,
        });
      this.#fieldIdx += diff.value;
      if (this.#fieldIdx >= this.ids.fieldIdsSize)
        return this.#fail({
          kind: "member-index-exceeds-ids",
          offset: at,
          members: "fields",
          index: this.#fieldIdx,
          bound: this.ids.fieldIdsSize,
        });
      this.#fieldsLeft -= 1;
      return "field";
    }
    while (this.#methodsLeft === 0) {
      const next = this.#methodLists.shift();
      if (next === undefined) return "end";
      // encoded_method: method_idx_diff, access, code_off (at least three bytes).
      if (next > cursor.remaining / 3)
        return this.#fail({
          kind: "budget-exceeded",
          offset: cursor.offset,
          resource: "class-data",
          declared: next,
          remaining: cursor.remaining,
        });
      this.#methodsLeft = next;
      this.#methodIdx = 0; // indices are cumulative deltas within each list
    }
    if (!charge()) return this.#fail(workSpentError(cursor));
    const at = cursor.offset;
    const diff = cursor.uleb128();
    if (!diff.ok) return this.#fail(diff.error);
    const access = cursor.uleb128();
    if (!access.ok) return this.#fail(access.error);
    const codeOff = cursor.uleb128();
    if (!codeOff.ok) return this.#fail(codeOff.error);
    this.#methodIdx += diff.value;
    if (this.#methodIdx >= this.ids.methodIdsSize)
      return this.#fail({
        kind: "member-index-exceeds-ids",
        offset: at,
        members: "methods",
        index: this.#methodIdx,
        bound: this.ids.methodIdsSize,
      });
    this.#accessFlags = access.value;
    this.#codeOff = codeOff.value;
    this.#methodsLeft -= 1;
    this.#methodCount += 1;
    return "method";
  }

  #fail(error: DexFileParseError): "failed" {
    this.#failure = error;
    return "failed";
  }
}

/** Read a `code_item` header at `offset`, exposing its `debug_info_off`. */
export const parseCodeItem = (
  bytes: Uint8Array,
  offset: number,
): Result<DexCodeItem, DexFileParseError> => {
  if (offset <= 0 || offset + 16 > bytes.length)
    return err({
      kind: "invalid-index",
      offset,
      index: offset,
      bound: bytes.length,
    });
  const cursor = new DexCursor(bytes, offset);
  const registersSize = cursor.u2();
  if (!registersSize.ok) return registersSize;
  const insSize = cursor.u2();
  if (!insSize.ok) return insSize;
  const outsSize = cursor.u2();
  if (!outsSize.ok) return outsSize;
  const triesSize = cursor.u2();
  if (!triesSize.ok) return triesSize;
  const debugInfoOff = cursor.u4();
  if (!debugInfoOff.ok) return debugInfoOff;
  const insnsSize = cursor.u4();
  if (!insnsSize.ok) return insnsSize;
  // The instructions (2 bytes per code unit) must lie inside the member, or
  // every position checked against insns_size would trust a fabricated size.
  if (offset + 16 + 2 * insnsSize.value > bytes.length)
    return err({
      kind: "invalid-index",
      offset,
      index: offset + 16 + 2 * insnsSize.value,
      bound: bytes.length,
    });
  return ok({
    registersSize: registersSize.value,
    insSize: insSize.value,
    outsSize: outsSize.value,
    triesSize: triesSize.value,
    debugInfoOff: debugInfoOff.value,
    insnsSize: insnsSize.value,
  });
};
