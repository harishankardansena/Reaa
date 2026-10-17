import { describe, expect, it } from "vitest";

import { displayName, displayNote, NamedMembers } from "./dexDisplayText.js";
import { DEX_LIMITS } from "./DexFileRelease.js";

describe("DEX display text", () => {
  it("keeps short names verbatim and marks a shortened one by its two ends", () => {
    expect(displayName("./classes2.dex", true)).toBe('"./classes2.dex"');
    const long = `${"./".repeat(1000)}classes7.dex`;
    const half = DEX_LIMITS.nameDisplayChars / 2;
    expect(displayName(long, true)).toBe(
      `${JSON.stringify(long.slice(0, half))}…${JSON.stringify(long.slice(-half))} (name shortened: ${String(DEX_LIMITS.nameDisplayChars)} of ${String(long.length)} characters shown)`,
    );
    expect(displayNote("x".repeat(5000))).toContain(
      `(note shortened: ${String(DEX_LIMITS.noteDisplayChars)} of 5000 characters shown)`,
    );
  });

  it("never splits a surrogate pair when shortening", () => {
    const half = DEX_LIMITS.nameDisplayChars / 2;
    const name = `${"a".repeat(half - 1)}😀${"b".repeat(500)}😀${"c".repeat(half - 1)}`;
    const shown = displayName(name);
    // Each cut falls inside a pair, so both halves of it are left out.
    expect(shown).toBe(
      `${"a".repeat(half - 1)}…${"c".repeat(half - 1)} (name shortened: ${String(2 * half - 2)} of ${String(name.length)} characters shown)`,
    );
  });

  it("counts every name past the byte budget and none twice", () => {
    const names = new NamedMembers(true);
    const huge = "y".repeat(100_000);
    for (let i = 0; i < 40; i += 1) names.add(`${huge}${String(i)}`);
    names.add(`${huge}0`);
    const kept = names.names.size;
    expect(kept).toBeGreaterThan(0);
    expect(kept + names.unnamed).toBe(40);
    const bytes = [...names.names].reduce(
      (sum, name) => sum + Buffer.byteLength(names.display(name)) + 2,
      0,
    );
    expect(bytes).toBeLessThanOrEqual(DEX_LIMITS.namedMembersBytes);
  });
});
