/**
 * "Modified UTF-8", the encoding used by both the JVM class-file constant pool
 * (JVMS §4.4.7) and the DEX `string_data_item` (Dalvik Executable format):
 * U+0000 is encoded as the two-byte `C0 80`, and supplementary characters are
 * encoded as a CESU-8 surrogate pair (two three-byte sequences), never as a
 * four-byte sequence.
 */

/**
 * Validate modified-UTF8 in place, allocating nothing. Returns the number of
 * UTF-16 code units it decodes to, or `null` on any malformed sequence — a
 * stray continuation byte used as a lead, a lead that promises continuation
 * bytes the buffer does not hold, a four-byte (0xF0+) lead that modified UTF-8
 * never emits, or an overlong (non-shortest) form, which both the JVM and
 * ART's DEX verifier reject. Callers attach their own positional context.
 */
export const modifiedUtf8Units = (bytes: Uint8Array): number | null => {
  const isContinuation = (byte: number | undefined): boolean =>
    byte !== undefined && (byte & 0xc0) === 0x80;
  let units = 0;
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a === 0 || a >= 0xf0) return null;
    if (a < 0x80) i += 1;
    else if (a < 0xe0) {
      // A 2-byte sequence leads with 110xxxxx (>= 0xc0); 0x80-0xbf are
      // continuation bytes and are never valid as a lead. (0xc0 0x80 remains
      // the modified-UTF8 encoding of U+0000 and stays accepted.)
      if (a < 0xc0 || !isContinuation(bytes[i + 1])) return null;
      // Shortest form only (JVMS §4.4.7): a 2-byte sequence encodes
      // U+0080..U+07FF, or U+0000 as exactly 0xC0 0x80. An overlong form
      // (e.g. 0xC0 0x81 for U+0001) is rejected, as the JVM rejects it.
      const unit = ((a & 0x1f) << 6) | (bytes[i + 1]! & 0x3f);
      if (unit < 0x80 && !(a === 0xc0 && bytes[i + 1] === 0x80)) return null;
      i += 2;
    } else {
      if (!isContinuation(bytes[i + 1]) || !isContinuation(bytes[i + 2]))
        return null;
      // Shortest form only: a 3-byte sequence encodes U+0800..U+FFFF.
      if (a === 0xe0 && bytes[i + 1]! < 0xa0) return null;
      i += 3;
    }
    units += 1;
  }
  return units;
};

const DECODE_CHUNK = 8192;

/**
 * Decode already-validated modified-UTF8 into one flat string. Code units are
 * written to a typed array and converted in bounded chunks: per-character
 * concatenation would build a rope of tens of thousands of nodes per string.
 * Lone surrogates are preserved exactly (a UTF-16 TextDecoder would replace
 * them).
 */
const decodeValidModifiedUtf8 = (bytes: Uint8Array, units: number): string => {
  const out = new Uint16Array(units);
  let u = 0;
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a < 0x80) {
      out[u] = a;
      i += 1;
    } else if (a < 0xe0) {
      out[u] = ((a & 0x1f) << 6) | (bytes[i + 1]! & 0x3f);
      i += 2;
    } else {
      out[u] =
        ((a & 0x0f) << 12) |
        ((bytes[i + 1]! & 0x3f) << 6) |
        (bytes[i + 2]! & 0x3f);
      i += 3;
    }
    u += 1;
  }
  let text = "";
  for (let at = 0; at < units; at += DECODE_CHUNK)
    text += String.fromCharCode(...out.subarray(at, at + DECODE_CHUNK));
  return text;
};

/** Validate and decode in one step; `null` when the bytes are malformed. */
export const decodeModifiedUtf8 = (bytes: Uint8Array): string | null => {
  const units = modifiedUtf8Units(bytes);
  return units === null ? null : decodeValidModifiedUtf8(bytes, units);
};

/**
 * Upper bound on the UTF-8 bytes `JSON.stringify` emits for modified-UTF8
 * `bytes` (quotes included), computed without decoding: control characters
 * escape to `\\u00XX`, quote/backslash to two bytes, and a 3-byte sequence is
 * charged 6 in case it is a lone surrogate (`\\udXXX`). Sound for anything
 * {@link modifiedUtf8Units} accepts, because overlong forms are rejected: a
 * control character can only arrive as one byte, or U+0000 as 0xC0 0x80.
 */
export const modifiedUtf8JsonBound = (bytes: Uint8Array): number => {
  let total = 2;
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a < 0x80) {
      total += a < 0x20 ? 6 : a === 0x22 || a === 0x5c ? 2 : 1;
      i += 1;
    } else if (a < 0xe0) {
      total += a === 0xc0 && bytes[i + 1] === 0x80 ? 6 : 2;
      i += 2;
    } else {
      total += a === 0xed ? 6 : 3;
      i += 3;
    }
  }
  return total;
};

/**
 * Encode text as modified UTF-8: U+0000 as `C0 80`, other BMP units as 1–3
 * bytes, and each surrogate of a supplementary character separately (CESU-8).
 */
export const encodeModifiedUtf8 = (text: string): Uint8Array => {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit !== 0 && unit < 0x80) bytes.push(unit);
    else if (unit < 0x800) bytes.push(0xc0 | (unit >> 6), 0x80 | (unit & 0x3f));
    else
      bytes.push(
        0xe0 | (unit >> 12),
        0x80 | ((unit >> 6) & 0x3f),
        0x80 | (unit & 0x3f),
      );
  }
  return Uint8Array.from(bytes);
};
