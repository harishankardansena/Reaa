import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { DexFileProvider } from "./DexFileProvider.js";
import { debuggableDex, zipArchive } from "../../tests/fixtures/dexFile.js";

let dir: string;
const provider = new DexFileProvider();

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "rea-dex-"));
});
afterAll(async () => {
  await provider.close();
  await rm(dir, { recursive: true, force: true });
});

const write = async (name: string, bytes: Uint8Array): Promise<string> => {
  const path = join(dir, name);
  await writeFile(path, bytes);
  return path;
};

describe("DexFileProvider loose .dex", () => {
  it("summarizes a loose dex with readiness present", async () => {
    const result = await provider.inspect({
      path: await write("a.dex", debuggableDex()),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as Record<string, unknown>;
    expect(r.container).toBe("dex-file");
    expect(r.mode).toBe("summary");
    const members = r.members as {
      entry: null;
      summary: { readiness: string };
    }[];
    expect(members).toHaveLength(1);
    expect(members[0]!.entry).toBeNull();
    expect(members[0]!.summary.readiness).toBe("present");
  });

  it("returns full per-method detail for a selected class", async () => {
    const result = await provider.inspect({
      path: await write("b.dex", debuggableDex()),
      class_descriptor: "Lcom/example/Foo;",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as {
      mode: string;
      class_detail: {
        source_file: string;
        methods: {
          name: string;
          descriptor: string;
          locals: { name: string | null; type: string | null }[];
        }[];
      };
    };
    expect(r.mode).toBe("class-detail");
    expect(r.class_detail.source_file).toBe("Foo.java");
    const method = r.class_detail.methods[0]!;
    expect(method.name).toBe("run");
    expect(method.descriptor).toBe("(I)V");
    // The implicit parameter local is seeded and resolved (regression guard).
    expect(method.locals).toContainEqual(
      expect.objectContaining({ name: "x", type: "I" }),
    );
  });

  it("refuses a class descriptor not present", async () => {
    const result = await provider.inspect({
      path: await write("c.dex", debuggableDex()),
      class_descriptor: "LNope;",
    });
    expect(result.ok).toBe(false);
  });
});

describe("DexFileProvider APK selection", () => {
  it("refuses an encrypted root member instead of silently skipping it", async () => {
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add("classes.dex", new Uint8ArrayReader(debuggableDex()), {
      password: "secret",
    });
    await writer.add("classes2.dex", new Uint8ArrayReader(debuggableDex()));
    const result = await provider.inspect({
      path: await write("encrypted.apk", await writer.close()),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    expect(result.error.message).toContain("classes.dex");
  });

  it("summarizes every root classes*.dex when no entry is given", async () => {
    const apk = await write(
      "app.apk",
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", bytes: debuggableDex() },
        { name: "res/raw/note.txt", bytes: Uint8Array.from([1, 2, 3]) },
      ]),
    );
    const result = await provider.inspect({ path: apk });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as {
      container: string;
      members: { entry: string }[];
    };
    expect(r.container).toBe("apk");
    expect(r.members.map((m) => m.entry)).toEqual([
      "classes.dex",
      "classes2.dex",
    ]);
  });

  it("auto-loads members by their stored name, as ART does", async () => {
    const dotted = await write(
      "dotted.apk",
      await zipArchive([
        { name: "./classes.dex", bytes: debuggableDex() },
        { name: "classes.dex", bytes: debuggableDex() },
      ]),
    );
    const result = await provider.inspect({ path: dotted });
    // Only the plain stored name loads; `./classes.dex` is not ambiguous with it.
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as { members: { entry: string }[] };
    expect(r.members.map((m) => m.entry)).toEqual(["classes.dex"]);
    const onlyDotted = await provider.inspect({
      path: await write(
        "only-dotted.apk",
        await zipArchive([{ name: "./classes.dex", bytes: debuggableDex() }]),
      ),
    });
    expect(onlyDotted.ok).toBe(false);
  });

  it("reports bytes after file_size as unread instead of refusing the DEX", async () => {
    const dex = debuggableDex();
    const padded = new Uint8Array(dex.length + 5);
    padded.set(dex);
    const result = await provider.inspect({
      path: await write("trailing.dex", padded),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.limitations.at(-1)).toContain("5 bytes after");
  });

  it("keeps the unread-trailing-bytes fact on a refused class lookup", async () => {
    const dex = debuggableDex();
    const padded = new Uint8Array(dex.length + 3);
    padded.set(dex);
    const result = await provider.inspect({
      path: await write("trailing-absent.dex", padded),
      class_descriptor: "LAbsent;",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message + JSON.stringify(result.error)).toContain(
      "3 bytes after",
    );
  });

  it("names canonical members Android would not auto-load after a gap", async () => {
    const result = await provider.inspect({
      path: await write(
        "gap.apk",
        await zipArchive([
          { name: "classes.dex", bytes: debuggableDex() },
          { name: "classes3.dex", bytes: debuggableDex() },
        ]),
      ),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as { members: { entry: string }[] };
    expect(r.members.map((m) => m.entry)).toEqual(["classes.dex"]);
    expect(result.value.limitations.join(" ")).toContain(
      "also holds classes3.dex",
    );
  });

  it("selects one dex member by entry", async () => {
    const apk = await write(
      "one.apk",
      await zipArchive([{ name: "classes.dex", bytes: debuggableDex() }]),
    );
    const result = await provider.inspect({ path: apk, entry: "classes.dex" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as { members: { entry: string }[] };
    expect(r.members[0]!.entry).toBe("classes.dex");
  });

  it("reports a missing entry as an input error", async () => {
    const apk = await write(
      "miss.apk",
      await zipArchive([{ name: "classes.dex", bytes: debuggableDex() }]),
    );
    const result = await provider.inspect({ path: apk, entry: "classes9.dex" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("steers a non-dex, non-zip file to a useful refusal", async () => {
    const result = await provider.inspect({
      path: await write("x.bin", Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8])),
    });
    expect(result.ok).toBe(false);
  });
});

describe("DexFileProvider members Android does not auto-load", () => {
  it("names canonical members past the retained member cap", async () => {
    const members = Array.from({ length: 64 }, (_, i) => ({
      name: i === 0 ? "classes.dex" : `classes${String(i + 1)}.dex`,
      bytes: debuggableDex(),
    }));
    members.push({ name: "classes66.dex", bytes: debuggableDex() });
    const result = await provider.inspect({
      path: await write("cap-gap.apk", await zipArchive(members)),
      class_descriptor: "LAbsent;",
    });
    if (result.ok) throw new Error("Expected an absent class");
    expect(result.error.message + JSON.stringify(result.error)).toContain(
      "also holds classes66.dex",
    );
  });

  it("attributes an over-cap refusal to the limit, not to Android", async () => {
    const members = Array.from({ length: 66 }, (_, i) => ({
      name: i === 0 ? "classes.dex" : `classes${String(i + 1)}.dex`,
      bytes: debuggableDex(),
    }));
    members.push({ name: "classes70.dex", bytes: debuggableDex() });
    const result = await provider.inspect({
      path: await write("over-cap.apk", await zipArchive(members)),
    });
    if (result.ok) throw new Error("Expected an over-cap refusal");
    const message = result.error.message;
    expect(message).toContain(
      "auto-loads 66 DEX members (classes.dex … classes66.dex), more than the 64-member limit",
    );
    // Only the member after the gap is one Android does not auto-load.
    expect(message).toContain(
      "also holds classes70.dex, which Android does not auto-load",
    );
  });

  it("names skipped members on a selection refusal", async () => {
    const result = await provider.inspect({
      path: await write(
        "no-root.apk",
        await zipArchive([
          { name: "classes2.dex", bytes: debuggableDex() },
          { name: "classes3.dex", bytes: debuggableDex() },
        ]),
      ),
    });
    if (result.ok) throw new Error("Expected a refusal");
    expect(JSON.stringify(result.error)).toContain(
      "also holds classes2.dex, classes3.dex",
    );
  });

  it("explains a member stored under a non-exact name as not auto-loaded", async () => {
    const result = await provider.inspect({
      path: await write(
        "dot-stored.apk",
        await zipArchive([
          { name: "classes.dex", bytes: debuggableDex() },
          { name: "./classes2.dex", bytes: debuggableDex() },
          { name: "classes3.dex", bytes: debuggableDex() },
        ]),
      ),
    });
    if (!result.ok) throw new Error("Expected a summary");
    const note = result.value.limitations.join(" ");
    expect(note).toContain("also holds ./classes2.dex, classes3.dex");
    expect(note).toContain("present under its exact stored name");
  });
});

describe("DexFileProvider stored member names", () => {
  const first = debuggableDex();
  const second = debuggableDex(3);
  const digest = (bytes: Uint8Array): string =>
    createHash("sha256").update(bytes).digest("hex");
  type Members = { members: { entry: string; sha256: string }[] };
  const members = async (path: string, entry?: string) => {
    const result = await provider.inspect({
      path,
      ...(entry === undefined ? {} : { entry }),
    });
    if (!result.ok) return { error: result.error._tag };
    return {
      members: (result.value.result as Members).members.map(
        (m) =>
          `${m.entry}:${m.sha256 === digest(first) ? "first" : m.sha256 === digest(second) ? "second" : "other"}`,
      ),
      limitations: result.value.limitations,
    };
  };

  it("loads and selects by the stored name, ignoring a Unicode Path name as ART does", async () => {
    // Stored classes2.dex whose Unicode Path names foo.txt: ART loads it.
    const hidden = await write(
      "up-hides.apk",
      await zipArchive([
        { name: "classes.dex", bytes: first },
        { name: "classes2.dex", bytes: second, unicodePath: "foo.txt" },
      ]),
    );
    const auto = await members(hidden);
    expect(auto.members).toEqual(["classes.dex:first", "classes2.dex:second"]);
    // The reader's note on the selected member reaches the report.
    expect(auto.limitations?.join("\n")).toContain(
      'stored name "classes2.dex" differs from its Info-ZIP Unicode Path extra field name "foo.txt"',
    );
    expect((await members(hidden, "classes2.dex")).members).toEqual([
      "classes2.dex:second",
    ]);
    expect(await members(hidden, "foo.txt")).toEqual({
      error: "AnalysisInputError",
    });

    // A Unicode Path claiming classes.dex neither loads nor selects foo.dex as it.
    const faked = await write(
      "up-fakes.apk",
      await zipArchive([
        { name: "foo.dex", bytes: first, unicodePath: "classes.dex" },
      ]),
    );
    expect(await members(faked)).toEqual({ error: "AnalysisInputError" });
    expect(await members(faked, "classes.dex")).toEqual({
      error: "AnalysisInputError",
    });
    expect((await members(faked, "foo.dex")).members).toEqual([
      "foo.dex:first",
    ]);

    // Stored classes2.dex renamed classes.dex is not a second classes.dex.
    const twin = await write(
      "up-twin.apk",
      await zipArchive([
        { name: "classes.dex", bytes: first },
        { name: "classes2.dex", bytes: second, unicodePath: "classes.dex" },
      ]),
    );
    expect((await members(twin)).members).toEqual([
      "classes.dex:first",
      "classes2.dex:second",
    ]);
    expect((await members(twin, "classes.dex")).members).toEqual([
      "classes.dex:first",
    ]);
  });

  it("reports a ./-prefixed stored name as the selected member's identity", async () => {
    const dotted = await write(
      "dot-c2.apk",
      await zipArchive([
        { name: "classes.dex", bytes: first },
        { name: "./classes2.dex", bytes: second, unicodePath: "classes2.dex" },
      ]),
    );
    expect((await members(dotted)).members).toEqual(["classes.dex:first"]);
    for (const entry of ["classes2.dex", "./classes2.dex"])
      expect((await members(dotted, entry)).members).toEqual([
        "./classes2.dex:second",
      ]);
  });

  it("carries the reader's attribute note on a member it reads", async () => {
    const apk = await write(
      "dirmode.apk",
      await zipArchive([
        {
          name: "classes.dex",
          bytes: first,
          externalFileAttributes: 0o040755 * 0x10000,
        },
      ]),
    );
    const auto = await members(apk);
    expect(auto.members).toEqual(["classes.dex:first"]);
    expect(auto.limitations?.join("\n")).toContain(
      'ZIP member "classes.dex" has directory external attributes',
    );
  });
});
