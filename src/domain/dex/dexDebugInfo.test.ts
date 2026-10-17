import { describe, expect, it } from "vitest";

import { decodeDebugInfo } from "./dexDebugInfo.js";
import {
  dexParameterList,
  sleb,
  uleb,
  ulebp1,
} from "../../../tests/fixtures/dexFile.js";

// Opcodes
const END_SEQUENCE = 0x00;
const ADVANCE_LINE = 0x02;
const START_LOCAL = 0x03;
const END_LOCAL = 0x05;
const SET_FILE = 0x09;
const ADVANCE_PC = 0x01;
const EMIT_HERE = 0x0e; // special opcode: line += 0, address += 0, emit a position

/** Assemble a debug_info_item at offset 1 (offset 0 is reserved for "absent"). */
const stream = (...body: number[]): Uint8Array =>
  Uint8Array.from([0xff, ...body]);

describe("decodeDebugInfo", () => {
  it("decodes parameter names, a position, and a closed local scope", () => {
    const bytes = stream(
      ...uleb(1), // line_start
      ...uleb(1), // parameters_size
      ...ulebp1(5), // parameter name_idx = 5
      START_LOCAL,
      ...uleb(1), // register
      ...ulebp1(10), // name_idx
      ...ulebp1(11), // type_idx
      EMIT_HERE, // position @ address 0, line 1
      ADVANCE_PC,
      ...uleb(2), // the scope covers addresses 0-1
      END_LOCAL,
      ...uleb(1), // register
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 10);
    expect(d.present).toBe(true);
    expect(d.malformed).toBe(false);
    expect(d.parameterNames).toEqual([5]);
    expect(d.positionCount).toBe(1);
    expect(d.locals).toHaveLength(1);
    expect(d.locals[0]).toMatchObject({
      register: 1,
      nameIdx: 10,
      typeIdx: 11,
      signatureIdx: -1,
      startAddress: 0,
      endAddress: 2,
      outOfRange: false,
    });
  });

  it("skips a zero-length scope, as dexdump does", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(1),
      ...ulebp1(10),
      ...ulebp1(11),
      END_LOCAL, // ends at its own start address
      ...uleb(1),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 10);
    expect(d.localCount).toBe(0);
    expect(d.explicitLocalCount).toBe(0);
  });

  it("counts a declaration only when a scope covers an in-code instruction", () => {
    const zeroLength = Array.from({ length: 50 }, () => [
      START_LOCAL,
      ...uleb(1),
      ...ulebp1(10),
      ...ulebp1(11),
      END_LOCAL,
      ...uleb(1),
    ]).flat();
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      ...zeroLength,
      START_LOCAL, // a real scope over addresses 0-1, ended and restarted
      ...uleb(2),
      ...ulebp1(10),
      ...ulebp1(11),
      ADVANCE_PC,
      ...uleb(2),
      END_LOCAL,
      ...uleb(2),
      0x06, // DBG_RESTART_LOCAL: the same declaration, not a new one
      ...uleb(2),
      ADVANCE_PC,
      ...uleb(10), // past insns_size
      START_LOCAL, // declared past the code: covers no instruction
      ...uleb(3),
      ...ulebp1(10),
      ...ulebp1(11),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.explicitLocalCount).toBe(1);
    expect(d.explicitLocalCount).toBeLessThanOrEqual(d.localCount);
  });

  it("runs an unterminated local scope to insns_size", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(2),
      ...ulebp1(3),
      ...ulebp1(4),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 7);
    expect(d.malformed).toBe(false);
    expect(d.locals[0]).toMatchObject({ startAddress: 0, endAddress: 7 });
  });

  it("marks malformed when a local is ended on an empty register", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      END_LOCAL,
      ...uleb(4),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(true);
  });

  it("counts a SET_FILE redirect and the position after it", () => {
    const bytes = stream(
      ...uleb(5),
      ...uleb(0),
      SET_FILE,
      ...ulebp1(7),
      EMIT_HERE,
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.setFileEvents).toBe(1);
    expect(d.positionCount).toBe(1);
    expect(d.malformed).toBe(false);
  });

  it("preserves a position but marks malformed when a line goes non-positive", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      ADVANCE_LINE,
      ...sleb(-5),
      EMIT_HERE, // line 1 - 5 + 0 = -4
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.positionCount).toBe(1);
    expect(d.malformed).toBe(true);
  });

  it("marks malformed when the stream ends without DBG_END_SEQUENCE", () => {
    const bytes = stream(...uleb(1), ...uleb(0), EMIT_HERE); // no END_SEQUENCE
    const d = decodeDebugInfo(bytes, 1, 4);
    expect(d.malformed).toBe(true);
    expect(d.positionCount).toBe(1);
  });
});

describe("decodeDebugInfo bounds and semantics", () => {
  it("counts only positions inside the method's code", () => {
    // Special opcode 0x1e: address += 1, line += 1 (a shared R8 stream runs on).
    const ADVANCE_BOTH = 0x0a + 15 + 1;
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      EMIT_HERE,
      ADVANCE_BOTH,
      ADVANCE_BOTH,
      ADVANCE_BOTH,
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 2);
    expect(d.positionCount).toBe(2);
  });

  it("separates declared locals from implicit parameter locals", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(1),
      ...ulebp1(-1 + 0), // one unnamed parameter (name index NO_INDEX)
      START_LOCAL,
      ...uleb(1), // a register other than the seeded parameter's
      ...ulebp1(10),
      ...ulebp1(11),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4, {
      firstRegister: 0,
      accessFlags: 0x8,
      thisTypeIdx: 0,
      paramTypes: dexParameterList([{ typeIdx: 3, wide: false }]),
    });
    expect(d.explicitLocalCount).toBe(1);
    expect(d.localCount).toBeGreaterThan(d.explicitLocalCount);
  });

  it("refuses a parameter list longer than 255 before allocating it", () => {
    const d = decodeDebugInfo(stream(...uleb(1), ...uleb(256)), 1, 4);
    expect(d.malformed).toBe(true);
    expect(d.parameterNames).toEqual([]);
  });
});

describe("decodeDebugInfo register bound", () => {
  it("treats a local in a register past registers_size as malformed", () => {
    const bytes = stream(
      ...uleb(1),
      ...uleb(0),
      START_LOCAL,
      ...uleb(70_000),
      ...ulebp1(10),
      ...ulebp1(11),
      END_SEQUENCE,
    );
    const d = decodeDebugInfo(bytes, 1, 4, {
      firstRegister: 0,
      registersSize: 4,
      accessFlags: 0x8,
      thisTypeIdx: 0,
      paramTypes: dexParameterList([]),
    });
    expect(d.malformed).toBe(true);
    expect(d.localCount).toBe(0);
  });
});
