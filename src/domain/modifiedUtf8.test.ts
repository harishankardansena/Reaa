import { describe, expect, it } from "vitest";

import {
  decodeModifiedUtf8,
  encodeModifiedUtf8,
  modifiedUtf8Units,
} from "./modifiedUtf8.js";

describe("decodeModifiedUtf8", () => {
  it("decodes ASCII", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0x41, 0x42]))).toBe("AB");
  });

  it("decodes the two-byte C0 80 encoding of U+0000", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xc0, 0x80]))).toBe("\u0000");
  });

  it("decodes a two-byte BMP character", () => {
    // U+00E9 é -> C3 A9
    expect(decodeModifiedUtf8(Uint8Array.from([0xc3, 0xa9]))).toBe("é");
  });

  it("decodes a CESU-8 supplementary pair to its UTF-16 surrogates", () => {
    // U+1F600 -> surrogates D83D DE00, each a three-byte sequence
    const bytes = Uint8Array.from([0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
    expect(decodeModifiedUtf8(bytes)).toBe("😀");
  });

  it("rejects a stray continuation byte used as a lead", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0x80, 0x80]))).toBeNull();
  });

  it("rejects a four-byte (0xF0+) lead that modified UTF-8 never emits", () => {
    expect(
      decodeModifiedUtf8(Uint8Array.from([0xf0, 0x9f, 0x98, 0x80])),
    ).toBeNull();
  });

  it("rejects a truncated multi-byte sequence", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xe0, 0x80]))).toBeNull();
  });
});

describe("modified UTF-8 hardening shared by the JVM and DEX readers", () => {
  it("rejects overlong forms, as the JVM and ART's DEX verifier do", () => {
    for (const overlong of [
      [0xc0, 0x81],
      [0xc1, 0xbf],
      [0xe0, 0x81, 0x81],
      [0xe0, 0x9f, 0xbf],
    ])
      expect(decodeModifiedUtf8(Uint8Array.from(overlong))).toBeNull();
  });

  it("keeps U+0000 as 0xC0 0x80 and the shortest 2- and 3-byte forms", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xc0, 0x80]))).toBe("\u0000");
    expect(decodeModifiedUtf8(Uint8Array.from([0xc2, 0x80]))).toBe("\u0080");
    expect(decodeModifiedUtf8(Uint8Array.from([0xe0, 0xa0, 0x80]))).toBe(
      "\u0800",
    );
  });

  it("preserves a lone surrogate exactly and decodes long strings flat", () => {
    expect(decodeModifiedUtf8(Uint8Array.from([0xed, 0xa0, 0x80]))).toBe(
      "\ud800",
    );
    const long = Uint8Array.from({ length: 20_000 }, () => 0x61);
    expect(decodeModifiedUtf8(long)).toBe("a".repeat(20_000));
  });
});

describe("encodeModifiedUtf8", () => {
  it("round-trips through the decoder, including NUL and supplementary text", () => {
    for (const text of [
      "Lcom/example/Foo;",
      "a\u0000b",
      "\u00fc\u4e2d",
      "\ud83d\ude00",
    ]) {
      const encoded = encodeModifiedUtf8(text);
      expect(decodeModifiedUtf8(encoded)).toBe(text);
      expect(modifiedUtf8Units(encoded)).toBe(text.length);
    }
    expect([...encodeModifiedUtf8("\u0000")]).toEqual([0xc0, 0x80]);
  });
});
