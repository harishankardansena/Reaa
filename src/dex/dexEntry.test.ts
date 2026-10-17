import { describe, expect, it } from "vitest";

import { autoLoadedDexMembers, multidexIndex } from "./dexEntry.js";

describe("multidex member selection", () => {
  it("accepts only the names ART generates", () => {
    expect(
      ["classes.dex", "classes2.dex", "classes10.dex"].map(multidexIndex),
    ).toEqual([0, 1, 9]);
    for (const name of [
      "classes1.dex",
      "classes0.dex",
      "classes01.dex",
      "classes02.dex",
      "lib/classes.dex",
      "classes.dex.bak",
    ])
      expect(multidexIndex(name)).toBeNull();
  });

  it("follows ART's load order and stops at the first gap", () => {
    expect(
      autoLoadedDexMembers([
        "classes3.dex",
        "classes.dex",
        "classes2.dex",
        "classes5.dex",
      ]),
    ).toEqual(["classes.dex", "classes2.dex", "classes3.dex"]);
    expect(autoLoadedDexMembers(["classes2.dex"])).toEqual([]);
  });
});
