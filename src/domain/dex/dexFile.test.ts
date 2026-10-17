import { describe, expect, it } from "vitest";

import {
  DEX_NO_INDEX,
  DexClassDataReader,
  type DexEncodedMethod,
  type DexWorkCharge,
  readClassDef,
  parseCodeItem,
  parseDexFile,
} from "./dexFile.js";
import { uleb } from "../../../tests/fixtures/dexFile.js";

/**
 * Assemble a minimal valid DEX with one class carrying one direct method whose
 * code_item references a debug_info_item. Layout (little-endian):
 *   header[0x70] | class_def[32] @0x70 | code_item[16] @0x90 | class_data @0xA0
 * The id pools are empty (size 0); framing never resolves their contents.
 */
const CLASS_DEFS_OFF = 0x70;
const CODE_ITEM_OFF = 0x90;
const CLASS_DATA_OFF = 0xa0;
const DEBUG_INFO_OFF = 500; // sentinel; framing reads the field, never follows it
const IDS = { fieldIdsSize: 1 << 20, methodIdsSize: 1 << 20 };

/** Open and step a class_data to its end, collecting methods and the outcome. */
const readClassData = (
  bytes: Uint8Array,
  offset: number,
  charge: DexWorkCharge = () => true,
  ids = IDS,
) => {
  const opened = DexClassDataReader.open(bytes, offset, ids);
  if (!opened.ok) return { methods: [], error: opened.error };
  const reader = opened.value;
  const methods: DexEncodedMethod[] = [];
  for (;;) {
    const step = reader.step(charge);
    if (step === "method") methods.push(reader.method);
    else if (step === "failed") return { methods, error: reader.failure };
    else if (step === "end") return { methods, error: null };
  }
};

const minimalDex = (version = "035"): Uint8Array => {
  const classData = [
    ...uleb(0), // static_fields_size
    ...uleb(0), // instance_fields_size
    ...uleb(1), // direct_methods_size
    ...uleb(0), // virtual_methods_size
    ...uleb(0), // method_idx_diff
    ...uleb(1), // access_flags
    ...uleb(CODE_ITEM_OFF), // code_off
  ];
  const total = CLASS_DATA_OFF + classData.length;
  const bytes = new Uint8Array(total);
  const dv = new DataView(bytes.buffer);
  // magic
  bytes.set([0x64, 0x65, 0x78, 0x0a], 0); // "dex\n"
  bytes.set(
    [...version].map((c) => c.charCodeAt(0)),
    4,
  );
  bytes[7] = 0x00;
  dv.setUint32(32, total, true); // file_size
  dv.setUint32(36, 0x70, true); // header_size
  dv.setUint32(40, 0x12345678, true); // endian_tag
  dv.setUint32(96, 1, true); // class_defs_size
  dv.setUint32(100, CLASS_DEFS_OFF, true); // class_defs_off
  // class_def_item @ 0x70
  dv.setUint32(CLASS_DEFS_OFF + 0, 0, true); // class_idx
  dv.setUint32(CLASS_DEFS_OFF + 4, 1, true); // access_flags
  dv.setUint32(CLASS_DEFS_OFF + 8, DEX_NO_INDEX, true); // superclass_idx
  dv.setUint32(CLASS_DEFS_OFF + 16, 0, true); // source_file_idx -> string 0
  dv.setUint32(CLASS_DEFS_OFF + 24, CLASS_DATA_OFF, true); // class_data_off
  // code_item @ 0x90
  dv.setUint16(CODE_ITEM_OFF + 0, 2, true); // registers_size
  dv.setUint16(CODE_ITEM_OFF + 2, 1, true); // ins_size
  dv.setUint16(CODE_ITEM_OFF + 4, 0, true); // outs_size
  dv.setUint16(CODE_ITEM_OFF + 6, 0, true); // tries_size
  dv.setUint32(CODE_ITEM_OFF + 8, DEBUG_INFO_OFF, true); // debug_info_off
  dv.setUint32(CODE_ITEM_OFF + 12, 0, true); // insns_size
  // class_data_item @ 0xA0
  bytes.set(classData, CLASS_DATA_OFF);
  return bytes;
};

describe("parseDexFile framing", () => {
  it("frames the header and a class_def with its source-file index", () => {
    const result = parseDexFile(minimalDex());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.header.version).toBe("035");
    expect(result.value.header.classDefsSize).toBe(1);
    const def = readClassDef(minimalDex(), result.value.header, 0);
    expect(def.sourceFileIdx).toBe(0);
    expect(def.superclassIdx).toBe(DEX_NO_INDEX);
    expect(def.classDataOff).toBe(CLASS_DATA_OFF);
  });

  it("decodes the class_data method list and reaches the code item's debug_info_off", () => {
    const bytes = minimalDex();
    const { methods, error } = readClassData(bytes, CLASS_DATA_OFF);
    expect(error).toBeNull();
    expect(methods).toHaveLength(1);
    const method = methods[0]!;
    expect(method.codeOff).toBe(CODE_ITEM_OFF);
    const code = parseCodeItem(bytes, method.codeOff);
    expect(code.ok).toBe(true);
    if (!code.ok) return;
    expect(code.value.debugInfoOff).toBe(DEBUG_INFO_OFF);
    expect(code.value.insnsSize).toBe(0);
  });

  it("refuses a file_size past the bytes present, naming it", () => {
    const bytes = minimalDex();
    new DataView(bytes.buffer).setUint32(32, 999999, true);
    const result = parseDexFile(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatchObject({ kind: "bad-header", offset: 32 });
  });

  it("refuses a file_size smaller than the header, naming it", () => {
    const bytes = minimalDex();
    new DataView(bytes.buffer).setUint32(32, 16, true);
    const result = parseDexFile(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatchObject({ kind: "bad-header", offset: 32 });
    if (result.error.kind === "bad-header")
      expect(result.error.detail).toContain("file_size 16");
  });

  it("frames on file_size and never reads trailing bytes, as ART 15+ does", () => {
    const dex = minimalDex();
    const bytes = new Uint8Array(dex.length + 7);
    bytes.set(dex);
    const result = parseDexFile(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.trailingBytes).toBe(7);
    expect(result.value.framed.length).toBe(dex.length);
  });

  it("refuses a non-dex buffer as bad-magic", () => {
    const bytes = minimalDex();
    bytes[1] = 0x00;
    const result = parseDexFile(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("bad-magic");
  });

  it("refuses compact dex (cdex) with its own reason", () => {
    const bytes = minimalDex();
    bytes.set([0x63, 0x64, 0x65, 0x0a], 0); // "cde\n"
    const result = parseDexFile(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("compact-dex");
  });

  it("refuses a reverse-endian file distinctly from an unsupported version", () => {
    const bytes = minimalDex();
    new DataView(bytes.buffer).setUint32(40, 0x78563412, true);
    const result = parseDexFile(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("reverse-endian");
  });

  it("refuses a withdrawn/future version (036, 041)", () => {
    for (const v of ["036", "041"]) {
      const result = parseDexFile(minimalDex(v));
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.kind).toBe("unsupported-version");
    }
  });

  it("reports truncation rather than throwing on a short header", () => {
    const result = parseDexFile(new Uint8Array(16));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("truncated");
  });

  it("refuses an impossible class_defs count instead of allocating", () => {
    const bytes = minimalDex();
    new DataView(bytes.buffer).setUint32(96, 0xffff, true); // class_defs_size
    const result = parseDexFile(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("budget-exceeded");
  });
});

describe("parseClassData bounds", () => {
  /** class_data at offset 1: field/method counts, then filler bytes. */
  const classData = (fields: number, filler: number): Uint8Array =>
    Uint8Array.from([
      0xff,
      ...uleb(fields),
      ...uleb(0),
      ...uleb(0),
      ...uleb(0),
      ...Array.from({ length: filler }, () => 0),
    ]);

  it("refuses a field count that cannot fit before walking it", () => {
    const { error } = readClassData(classData(1_000_000, 64), 1);
    expect(error).toMatchObject({
      kind: "budget-exceeded",
      resource: "class-data",
    });
  });

  it("charges every skipped field to the caller's work and stops when spent", () => {
    let units = 3;
    const { error } = readClassData(classData(10, 64), 1, () => units-- > 0);
    expect(error).toMatchObject({
      kind: "budget-exceeded",
      resource: "work",
    });
  });
});

describe("DexClassDataReader stepping", () => {
  /** class_data at offset 1 declaring `direct` methods with no code. */
  const methodsData = (direct: number, virtual = 0): Uint8Array =>
    Uint8Array.from([
      0xff,
      ...uleb(0),
      ...uleb(0),
      ...uleb(direct),
      ...uleb(virtual),
      ...Array.from({ length: direct + virtual }, () => [
        ...uleb(1),
        ...uleb(1),
        ...uleb(0),
      ]).flat(),
    ]);

  it("reads one entry per step, so a consumer can stop early", () => {
    const opened = DexClassDataReader.open(methodsData(5), 1, IDS);
    if (!opened.ok) throw new Error(opened.error.kind);
    expect(opened.value.step(() => true)).toBe("method");
    expect(opened.value.step(() => true)).toBe("method");
    expect(opened.value.methodCount).toBe(2);
    expect(opened.value.method).toEqual({
      methodIdx: 2,
      accessFlags: 1,
      codeOff: 0,
    });
  });

  it("reads lists that repeat an index, which ART accepts, however long", () => {
    // ART's CheckOrder rejects only a decreasing index, so a list may repeat
    // one id (diff 0) and be longer than the id table it indexes: two static
    // fields and three direct methods that all name id 0 are verifiable.
    const bytes = Uint8Array.from([
      0xff,
      ...uleb(2), // static_fields_size
      ...uleb(0), // instance_fields_size
      ...uleb(3), // direct_methods_size
      ...uleb(0), // virtual_methods_size
      ...[0, 8, 0, 8].flatMap((value) => uleb(value)), // field diffs 0, 0
      ...Array.from({ length: 3 }, () =>
        [0, 1, 0].flatMap((value) => uleb(value)),
      ).flat(),
    ]);
    const { methods, error } = readClassData(bytes, 1, () => true, {
      fieldIdsSize: 1,
      methodIdsSize: 1,
    });
    expect(error).toBeNull();
    expect(methods.map((method) => method.methodIdx)).toEqual([0, 0, 0]);
  });

  it("refuses an entry whose index is past its id table, as ART's CheckIndex does", () => {
    // Instance field indices restart at 0: static 0, then instance 0 and 1.
    const fields = Uint8Array.from([
      0xff,
      ...[1, 2, 0, 0].flatMap((value) => uleb(value)),
      ...[0, 8, 0, 0, 1, 0].flatMap((value) => uleb(value)),
    ]);
    expect(
      readClassData(fields, 1, () => true, {
        fieldIdsSize: 1,
        methodIdsSize: 0,
      }).error,
    ).toEqual({
      kind: "member-index-exceeds-ids",
      offset: 9,
      members: "fields",
      index: 1,
      bound: 1,
    });
    const { methods, error } = readClassData(methodsData(1, 1), 1, () => true, {
      fieldIdsSize: 0,
      methodIdsSize: 1,
    });
    // The direct method names id 1 (diff 1) past a one-entry table.
    expect(methods).toHaveLength(0);
    expect(error).toMatchObject({
      kind: "member-index-exceeds-ids",
      members: "methods",
      index: 1,
      bound: 1,
    });
  });
});
