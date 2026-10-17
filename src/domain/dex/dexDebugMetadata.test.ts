import { describe, expect, it } from "vitest";

import { dexWorkBudget } from "./dexDebugInfo.js";
import {
  assembleClassDetail,
  type DexWork,
  summarizeDex,
} from "./dexDebugMetadata.js";
import { parseDexFile } from "./dexFile.js";
import { debuggableDex, uleb } from "../../../tests/fixtures/dexFile.js";

const work = (limit = 1_000_000, cancelled = false): DexWork => ({
  budget: dexWorkBudget(limit),
  cancelled: () => cancelled,
  yieldNow: () => Promise.resolve(),
  sliceUnits: 1 << 18,
});
const OUTPUT_LIMIT = 8 * 1024 * 1024;

describe("dexDebugMetadata assembly", () => {
  it("summarizes a debuggable dex with resolved tallies and readiness", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await summarizeDex(parsed.value, debuggableDex(), work());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const summary = result.value;
    expect(summary.classCount).toBe(1);
    expect(summary.methodsWithCode).toBe(1);
    expect(summary.methodsWithDebugInfo).toBe(1);
    expect(summary.methodsWithParameterNames).toBe(1);
    expect(summary.linePositions).toBe(1);
    expect(summary.localDeclarations).toBe(1);
    expect(summary.sourceFilePresent).toBe(1);
    expect(summary.distinctSourceFiles).toEqual({
      count: 1,
      sample: ["Foo.java"],
    });
    expect(summary.readiness).toBe("present");
  });

  it("resolves full per-method detail for a selected class", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await assembleClassDetail(
      parsed.value,
      debuggableDex(),
      "Lcom/example/Foo;",
      work(),
      OUTPUT_LIMIT,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const detail = result.value;
    expect(detail).not.toBeNull();
    if (detail === null) return;
    expect(detail.sourceFile).toBe("Foo.java");
    expect(detail.methods).toHaveLength(1);
    const method = detail.methods[0]!;
    expect(method.name).toBe("run");
    expect(method.descriptor).toBe("(I)V");
    expect(method.state).toBe("present");
    expect(method.parameterNames).toEqual(["x"]);
    expect(method.locals).toHaveLength(1);
    expect(method.locals[0]).toMatchObject({
      register: 0,
      name: "x",
      type: "I",
      outOfRange: false,
    });
  });

  it("returns null for a class descriptor not present", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await assembleClassDetail(
      parsed.value,
      debuggableDex(),
      "LNope;",
      work(),
      OUTPUT_LIMIT,
    );
    expect(result).toEqual({ ok: true, value: null });
  });
});

describe("dexDebugMetadata work and output bounds", () => {
  it("refuses once the member's work budget is spent", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(await summarizeDex(parsed.value, debuggableDex(), work(1))).toEqual({
      ok: false,
      error: { kind: "work-budget-exceeded", limit: 1 },
    });
  });

  it("stops when the caller cancels", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(
      await summarizeDex(parsed.value, debuggableDex(), work(1_000_000, true)),
    ).toEqual({ ok: false, error: { kind: "cancelled" } });
  });

  it("refuses a class detail past the output limit before building it", async () => {
    const parsed = parseDexFile(debuggableDex());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await assembleClassDetail(
      parsed.value,
      debuggableDex(),
      "Lcom/example/Foo;",
      work(),
      1200,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("output-budget-exceeded");
  });
});

describe("dexDebugMetadata unreadable structures", () => {
  it("reports unreadable class_data and reads readiness as unknown, not stripped", async () => {
    const bytes = debuggableDex();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const classDefsOff = view.getUint32(100, true);
    view.setUint32(classDefsOff + 24, bytes.length + 100, true); // class_data_off past the file
    const parsed = parseDexFile(bytes);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const result = await summarizeDex(parsed.value, bytes, work());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.unreadable.classData).toBe(1);
    expect(result.value.readiness).toBe("unknown");
  });
});

/** Byte offsets of the fixture's class_def, class_data, code_item and debug_info. */
const layoutOf = (bytes: Uint8Array) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const classDefsOff = view.getUint32(100, true);
  const classDataOff = view.getUint32(classDefsOff + 24, true);
  const codeOff = classDataOff - 24; // 16-byte header + 4 code units
  return {
    view,
    classDefsOff,
    classDataOff,
    codeOff,
    debugInfoOff: codeOff - 5,
  };
};

/** The fixture with a second class_def (a copy whose class_idx is `classIdx`). */
const withSecondClassDef = (classIdx: number): Uint8Array => {
  const base = debuggableDex();
  const { classDefsOff } = layoutOf(base);
  const bytes = new Uint8Array(base.length + 32);
  bytes.set(base);
  bytes.set(base.subarray(classDefsOff, classDefsOff + 32), base.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(base.length, classIdx, true);
  view.setUint32(32, bytes.length, true); // file_size
  view.setUint32(96, 2, true); // class_defs_size
  return bytes;
};

const summaryOf = async (bytes: Uint8Array) => {
  const parsed = parseDexFile(bytes);
  if (!parsed.ok) throw new Error("fixture must frame");
  const result = await summarizeDex(parsed.value, bytes, work());
  if (!result.ok) throw new Error(result.error.kind);
  return result.value;
};

const detailOf = async (bytes: Uint8Array, limit = OUTPUT_LIMIT) => {
  const parsed = parseDexFile(bytes);
  if (!parsed.ok) throw new Error("fixture must frame");
  return await assembleClassDetail(
    parsed.value,
    bytes,
    "Lcom/example/Foo;",
    work(),
    limit,
  );
};

describe("dexDebugMetadata fails closed on unverifiable facts", () => {
  it("reports an unreadable class identity as unknown, never as absent", async () => {
    const result = await detailOf(withSecondClassDef(0xfffe));
    expect(result).toEqual({
      ok: false,
      error: { kind: "unreadable-class-identity", count: 1 },
    });
  });

  it("refuses a class declared by two class_defs as ambiguous", async () => {
    const result = await detailOf(withSecondClassDef(0));
    expect(result).toEqual({
      ok: false,
      error: { kind: "duplicate-class-definition", count: 2 },
    });
  });

  it("refuses an oversized methodless class before decoding its source file", async () => {
    const bytes = debuggableDex();
    const { view, classDefsOff } = layoutOf(bytes);
    view.setUint32(classDefsOff + 24, 0, true); // no class_data
    const result = await detailOf(bytes, 1030);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("output-budget-exceeded");
  });

  it("treats instructions running past the member as an unreadable code_item", async () => {
    const bytes = debuggableDex();
    const { view, codeOff } = layoutOf(bytes);
    view.setUint32(codeOff + 12, 0x7fff_ffff, true); // insns_size
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.codeItems).toBe(1);
    expect(summary.linePositions).toBe(0);
    expect(summary.readiness).toBe("unknown");
  });

  it("marks a parameter-name count that disagrees with the proto malformed", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 1] = 0; // parameters_size 0 for a one-parameter proto
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.methodsWithParameterNames).toBe(0);
    expect(summary.readiness).toBe("unknown");
  });

  it("does not count a local declaration that fails validation", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 3] = 0x03; // DBG_START_LOCAL
    bytes[debugInfoOff + 4] = 0x05; // register 5 of a 1-register frame
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.explicitLocalDeclarations).toBe(0);
  });
});

describe("dexDebugMetadata validates the frame and class identities", () => {
  it("marks a method whose ins_size disagrees with its proto malformed", async () => {
    const bytes = debuggableDex();
    const { view, codeOff } = layoutOf(bytes);
    view.setUint16(codeOff + 2, 0, true); // ins_size 0 for a one-int static method
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.debugInfo).toBe(1);
    expect(summary.readiness).toBe("unknown");
  });

  it("treats more incoming arguments than registers as an unreadable code_item", async () => {
    const bytes = debuggableDex();
    const { view, codeOff } = layoutOf(bytes);
    view.setUint16(codeOff + 2, 2, true); // ins_size 2 of a 1-register frame
    expect((await summaryOf(bytes)).unreadable.codeItems).toBe(1);
  });

  it("matches a class by its modified-UTF-8 bytes, not a near miss", async () => {
    const result = await detailOf(debuggableDex());
    expect(result.ok && result.value?.sourceFile).toBe("Foo.java");
    const parsed = parseDexFile(debuggableDex());
    if (!parsed.ok) throw new Error("fixture must frame");
    for (const near of ["Lcom/example/Foo", "Lcom/example/Fo\u00f6;", ""])
      expect(
        await assembleClassDetail(
          parsed.value,
          debuggableDex(),
          near,
          work(),
          OUTPUT_LIMIT,
        ),
      ).toEqual({ ok: true, value: null });
  });
});

describe("dexDebugMetadata readiness vocabulary", () => {
  it("labels a member with line positions but no local evidence partial", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 2] = 0; // parameter name NO_INDEX (an R8 release)
    const summary = await summaryOf(bytes);
    expect(summary.linePositions).toBe(1);
    expect(summary.explicitLocalDeclarations).toBe(0);
    expect(summary.methodsWithParameterNames).toBe(0);
    expect(summary.readiness).toBe("partial");
  });

  it("labels a member with local evidence but no line positions partial", async () => {
    const bytes = debuggableDex();
    const { debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 3] = 0x00; // END_SEQUENCE before the position
    const summary = await summaryOf(bytes);
    expect(summary.linePositions).toBe(0);
    expect(summary.readiness).toBe("partial");
  });

  it("keeps a partial member unknown when an unreadable structure could settle it", async () => {
    const bytes = withSecondClassDef(0);
    const { view, debugInfoOff } = layoutOf(bytes);
    bytes[debugInfoOff + 2] = 0; // lines only
    view.setUint32(bytes.length - 32 + 24, bytes.length + 100, true); // second class_data unreadable
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.classData).toBe(1);
    expect(summary.readiness).toBe("unknown");
  });
});

describe("dexDebugMetadata cooperative scheduling", () => {
  const pacedWork = (onYield: () => void, state: { aborted: boolean }) => ({
    budget: dexWorkBudget(1_000_000),
    cancelled: () => state.aborted,
    yieldNow: () => {
      onYield();
      return Promise.resolve();
    },
    sliceUnits: 1,
  });

  it("yields to the host between slices and observes an abort delivered there", async () => {
    const bytes = debuggableDex();
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const state = { aborted: false };
    let yields = 0;
    const work = pacedWork(() => {
      yields += 1;
      state.aborted = true;
    }, state);
    expect(await summarizeDex(parsed.value, bytes, work)).toEqual({
      ok: false,
      error: { kind: "cancelled" },
    });
    expect(yields).toBe(1);
  });

  it("yields during a class lookup and observes an abort delivered there", async () => {
    const bytes = withSecondClassDef(7);
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const state = { aborted: false };
    let yields = 0;
    const work = pacedWork(() => {
      yields += 1;
      state.aborted = true;
    }, state);
    expect(
      await assembleClassDetail(
        parsed.value,
        bytes,
        "Lcom/example/Foo;",
        work,
        OUTPUT_LIMIT,
      ),
    ).toEqual({ ok: false, error: { kind: "cancelled" } });
    expect(yields).toBe(1);
  });

  it("completes unchanged when the host keeps yielding without an abort", async () => {
    const bytes = debuggableDex();
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    let yields = 0;
    const result = await summarizeDex(
      parsed.value,
      bytes,
      pacedWork(() => (yields += 1), { aborted: false }),
    );
    expect(result.ok && result.value.readiness).toBe("present");
    expect(yields).toBeGreaterThan(0);
  });
});

/**
 * The fixture's class re-pointed at an appended class_data declaring `methods`
 * direct methods without code, with the header claiming `methodIds` method ids.
 */
const withCodelessMethods = (
  methods: number,
  methodIds: number,
  diff = 1,
): Uint8Array => {
  const base = debuggableDex();
  const classData = [
    ...uleb(0),
    ...uleb(0),
    ...uleb(methods),
    ...uleb(0),
    ...Array.from({ length: methods }, (_, i) => [
      ...uleb(i === 0 ? 0 : diff),
      ...uleb(1),
      ...uleb(0),
    ]).flat(),
  ];
  const bytes = new Uint8Array(base.length + classData.length);
  bytes.set(base);
  bytes.set(classData, base.length);
  const { view, classDefsOff } = layoutOf(bytes);
  view.setUint32(classDefsOff + 24, base.length, true); // class_data_off
  view.setUint32(32, bytes.length, true); // file_size
  view.setUint32(88, methodIds, true); // method_ids_size
  return bytes;
};

describe("dexDebugMetadata class_data validation", () => {
  it("paces the class_data validation pass, not only the method pass", async () => {
    const methods = 4096;
    const bytes = withCodelessMethods(methods, methods);
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const budget = dexWorkBudget(1_000_000);
    let usedAtFirstYield: number | null = null;
    const result = await summarizeDex(parsed.value, bytes, {
      budget,
      cancelled: () => usedAtFirstYield !== null,
      yieldNow: () => {
        usedAtFirstYield ??= budget.limit - budget.remaining;
        return Promise.resolve();
      },
      sliceUnits: 64,
    });
    expect(result).toEqual({ ok: false, error: { kind: "cancelled" } });
    // The abort lands one slice into validating the class's methods.
    expect(usedAtFirstYield).toBeGreaterThanOrEqual(64);
    expect(usedAtFirstYield).toBeLessThan(methods);
  });

  it("reads a method list that repeats an index past the id table's size, as ART accepts", async () => {
    // ART's CheckOrder rejects only a decreasing index: three direct methods
    // all naming method id 0 are verifiable though the table has one entry.
    const summary = await summaryOf(withCodelessMethods(3, 1, 0));
    expect(summary.unreadable.classData).toBe(0);
  });

  it("treats a method index past the method id table as unreadable class_data", async () => {
    const bytes = withCodelessMethods(2, 1);
    const summary = await summaryOf(bytes);
    expect(summary.unreadable.classData).toBe(1);
    expect(summary.readiness).toBe("unknown");
    expect(await detailOf(bytes)).toEqual({
      ok: false,
      error: {
        kind: "malformed-class-data",
        classDataOff: debuggableDex().length,
      },
    });
  });
});

describe("dexDebugMetadata distinct source files", () => {
  it("counts distinct string_ids but samples each text once", async () => {
    const bytes = withSecondClassDef(0);
    const { view } = layoutOf(bytes);
    const stringIdsOff = view.getUint32(60, true);
    // string_id 2 re-pointed at the data of string_id 0 ("Foo.java").
    view.setUint32(stringIdsOff + 8, view.getUint32(stringIdsOff, true), true);
    view.setUint32(bytes.length - 32 + 16, 2, true); // second source_file_idx
    const parsed = parseDexFile(bytes);
    if (!parsed.ok) throw new Error("fixture must frame");
    const result = await summarizeDex(parsed.value, bytes, work());
    if (!result.ok) throw new Error(result.error.kind);
    expect(result.value.distinctSourceFiles).toEqual({
      count: 2,
      sample: ["Foo.java"],
    });
  });
});
