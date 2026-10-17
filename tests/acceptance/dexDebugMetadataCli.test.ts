import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { toolContract } from "../../src/contracts/toolContracts.js";
import {
  debuggableDex,
  SYMLINK_ATTRIBUTES,
  zipArchive,
} from "../fixtures/dexFile.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest, type TestCli } from "../support/cli/cliFixture.js";

const TOOL = "inspect_dex_debug_metadata";
const CLASS = "Lcom/example/Foo;";

const evidenceOf = (value: unknown) =>
  toolContract(TOOL).outputSchema.parse(value);

cliTest(
  "summarizes, selects a member and drills into a class through the public CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-cli-");
    const apk = join(root, "app.apk");
    await writeFile(
      apk,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", bytes: debuggableDex() },
      ]),
    );

    const summary = await cli.run({
      arguments: ["inspect-dex-debug-metadata", apk, "--json"],
    });
    expect(summary.exitCode, summary.stderr).toBe(0);
    const summaryResult = evidenceOf(summary.json).normalized_result;
    if (summaryResult.mode !== "summary") throw new Error("Expected summary");
    expect(summaryResult.container).toBe("apk");
    expect(summaryResult.members.map((member) => member.entry)).toEqual([
      "classes.dex",
      "classes2.dex",
    ]);
    expect(summaryResult.members[0]?.summary.readiness).toBe("present");

    const entry = await cli.run({
      arguments: [
        "inspect-dex-debug-metadata",
        apk,
        "--entry",
        "classes2.dex",
        "--class-descriptor",
        CLASS,
        "--json",
      ],
    });
    expect(entry.exitCode, entry.stderr).toBe(0);
    const detail = evidenceOf(entry.json).normalized_result;
    if (detail.mode !== "class-detail") throw new Error("Expected detail");
    expect(detail.class_detail).toMatchObject({
      entry: "classes2.dex",
      descriptor: CLASS,
      source_file: "Foo.java",
      methods: [
        {
          name: "run",
          descriptor: "(I)V",
          state: "present",
          parameter_names: ["x"],
        },
      ],
    });

    const ambiguous = await cli.run({
      arguments: [
        "inspect-dex-debug-metadata",
        apk,
        "--class-descriptor",
        CLASS,
        "--json",
      ],
    });
    expect(ambiguous.exitCode).toBe(1);
    expect(ambiguous.json).toMatchObject({ code: "invalid_request" });
  },
);

cliTest(
  "selects a ./-stored member by either spelling and reports its stored name over CLI and MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-dot-");
    const apk = join(root, "dot.apk");
    await writeFile(
      apk,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "./classes2.dex", bytes: debuggableDex() },
      ]),
    );
    const { call } = await connectLocalToolsMcp();
    for (const entry of ["classes2.dex", "./classes2.dex"])
      for (const classDescriptor of [undefined, CLASS]) {
        const viaCli = await cli.run({
          arguments: [
            "inspect-dex-debug-metadata",
            apk,
            "--entry",
            entry,
            ...(classDescriptor === undefined
              ? []
              : ["--class-descriptor", classDescriptor]),
            "--json",
          ],
        });
        expect(viaCli.exitCode, viaCli.stdout + viaCli.stderr).toBe(0);
        const result = evidenceOf(viaCli.json).normalized_result;
        expect(
          result.mode === "summary"
            ? result.members.map((member) => member.entry)
            : [result.class_detail.entry],
        ).toEqual(["./classes2.dex"]);
        const viaMcp = await call(TOOL, {
          path: apk,
          entry,
          ...(classDescriptor === undefined
            ? {}
            : { class_descriptor: classDescriptor }),
        });
        expect(viaMcp.isError, JSON.stringify(viaMcp.content)).not.toBe(true);
        expect(evidenceOf(viaMcp.structuredContent).normalized_result).toEqual(
          result,
        );
      }
  },
);

cliTest(
  "prefers the exactly stored spelling, names spellings when none is exact, and refuses a ZIP directory as unavailable",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-spell-");
    const apk = join(root, "both.apk");
    await writeFile(
      apk,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", bytes: debuggableDex() },
        { name: "./classes2.dex", bytes: debuggableDex(5) },
      ]),
    );
    const select = (path: string, entry: string) =>
      cli.run({
        arguments: [
          "inspect-dex-debug-metadata",
          path,
          "--entry",
          entry,
          "--json",
        ],
      });
    for (const [entry, positions] of [
      ["classes2.dex", 1],
      ["./classes2.dex", 6],
    ] as const) {
      const selected = await select(apk, entry);
      expect(selected.exitCode, selected.stdout + selected.stderr).toBe(0);
      const result = evidenceOf(selected.json).normalized_result;
      if (result.mode !== "summary") throw new Error("Expected summary");
      expect(result.members).toMatchObject([
        { entry, summary: { line_positions: positions } },
      ]);
    }
    const neither = await select(apk, "././classes2.dex");
    expect(neither.exitCode).toBe(1);
    expect(neither.json).toMatchObject({ code: "invalid_request" });
    expect(JSON.stringify(neither.json)).toContain(
      String.raw`stored as \"classes2.dex\", \"./classes2.dex\"`,
    );

    const directory = join(root, "dir.apk");
    await writeFile(
      directory,
      await zipArchive([{ name: "classes.dex/", bytes: new Uint8Array() }]),
    );
    const refused = await select(directory, "classes.dex/");
    expect(refused.exitCode).toBe(1);
    expect(refused.json).toMatchObject({ code: "unsupported_target" });
    expect(JSON.stringify(refused.json)).toContain(
      "stored as a ZIP directory, which REA does not read as member bytes; its debug metadata is unavailable, not absent.",
    );
  },
);

const inspect = (cli: TestCli, path: string, entry?: string) =>
  cli.run({
    arguments: [
      "inspect-dex-debug-metadata",
      path,
      ...(entry === undefined ? [] : ["--entry", entry]),
      "--json",
    ],
  });

/** Every refusal message and limitation the CLI printed, joined. */
const prose = (json: unknown): string => JSON.stringify(json);

cliTest(
  "refuses a symbolic-link-mode DEX member as unavailable, never as absent or a shorter run",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-link-");
    const link = {
      bytes: debuggableDex(),
      externalFileAttributes: SYMLINK_ATTRIBUTES,
    };
    // ART ignores the unix mode and loads classes2.dex, so classes3.dex too.
    const inRun = join(root, "in-run.apk");
    await writeFile(
      inRun,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", ...link },
        { name: "classes3.dex", bytes: debuggableDex() },
      ]),
    );
    const auto = await inspect(cli, inRun);
    expect(auto.exitCode, auto.stdout).toBe(1);
    expect(auto.json).toMatchObject({ code: "unsupported_target" });
    expect(prose(auto.json)).toContain(
      "has root DEX member(s) stored with a symbolic-link mode (classes2.dex), which Android loads but REA does not read; their debug metadata is unavailable, not absent.",
    );
    for (const entry of ["classes2.dex", "./classes2.dex"]) {
      const selected = await inspect(cli, inRun, entry);
      expect(selected.exitCode, selected.stdout).toBe(1);
      expect(selected.json).toMatchObject({ code: "unsupported_target" });
      expect(prose(selected.json)).toContain(
        "is stored with a symbolic-link mode, which REA does not read; its debug metadata is unavailable, not absent.",
      );
    }

    const onlyLink = join(root, "only-link.apk");
    await writeFile(
      onlyLink,
      await zipArchive([{ name: "classes.dex", ...link }]),
    );
    const lone = await inspect(cli, onlyLink);
    expect(lone.json).toMatchObject({ code: "unsupported_target" });
    expect(prose(lone.json)).not.toContain("holds no classes.dex");

    // ART looks up the exact stored name, which is the link, not the ./ twin.
    const twin = join(root, "twin.apk");
    await writeFile(
      twin,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", ...link },
        { name: "./classes2.dex", bytes: debuggableDex(5) },
      ]),
    );
    const exact = await inspect(cli, twin, "classes2.dex");
    expect(exact.json).toMatchObject({ code: "unsupported_target" });
    const dotted = await inspect(cli, twin, "./classes2.dex");
    expect(dotted.exitCode, dotted.stdout).toBe(0);
    const result = evidenceOf(dotted.json).normalized_result;
    if (result.mode !== "summary") throw new Error("Expected summary");
    expect(result.members).toMatchObject([
      { entry: "./classes2.dex", summary: { line_positions: 6 } },
    ]);
    const neither = await inspect(cli, twin, "././classes2.dex");
    expect(neither.json).toMatchObject({ code: "invalid_request" });
    expect(prose(neither.json)).toContain("holds 2 members named classes2.dex");
  },
);

cliTest(
  "binds entry to the exact stored spelling: after a crowd, three times, and when encrypted",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-exact-");
    const crowd = join(root, "crowd.apk");
    await writeFile(
      crowd,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 5 }, () => ({
          name: "./classes2.dex",
          bytes: debuggableDex(5),
        })),
        { name: "classes2.dex", bytes: debuggableDex(2) },
      ]),
    );
    const late = await inspect(cli, crowd, "classes2.dex");
    expect(late.exitCode, late.stdout).toBe(0);
    const result = evidenceOf(late.json).normalized_result;
    if (result.mode !== "summary") throw new Error("Expected summary");
    expect(result.members).toMatchObject([
      { entry: "classes2.dex", summary: { line_positions: 3 } },
    ]);

    const thrice = join(root, "thrice.apk");
    await writeFile(
      thrice,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 3 }, () => ({
          name: "classes2.dex",
          bytes: debuggableDex(),
        })),
      ]),
    );
    const repeated = await inspect(cli, thrice, "classes2.dex");
    expect(repeated.json).toMatchObject({ code: "invalid_request" });
    expect(prose(repeated.json)).toContain(
      String.raw`holds 3 members stored as \"classes2.dex\"; the identity is ambiguous.`,
    );

    const locked = join(root, "locked.apk");
    await writeFile(
      locked,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        { name: "classes2.dex", bytes: debuggableDex(), password: "secret" },
        { name: "./classes2.dex", bytes: debuggableDex(5) },
      ]),
    );
    const encrypted = await inspect(cli, locked, "classes2.dex");
    expect(encrypted.json).toMatchObject({ code: "unsupported_target" });
    expect(prose(encrypted.json)).toContain("is encrypted");
    const plain = await inspect(cli, locked, "./classes2.dex");
    expect(plain.exitCode, plain.stdout).toBe(0);
  },
);

cliTest(
  "names members within a count and byte budget and counts the rest accurately",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-budget-");
    // 131 canonical names after a gap: 128 named (classes.dex among them).
    const gap = join(root, "gap.apk");
    await writeFile(
      gap,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 130 }, (_, i) => ({
          name: `classes${String(i + 3)}.dex`,
          bytes: debuggableDex(),
        })),
      ]),
    );
    const capped = await inspect(cli, gap);
    expect(capped.exitCode, capped.stdout).toBe(0);
    const note = evidenceOf(capped.json).normalized_result.limitations.join(
      " ",
    );
    expect(note).toContain("classes129.dex, 3 more canonical DEX member(s)");
    expect(note).not.toContain("classes130.dex");

    // Spellings past the byte budget are counted as members, not spellings:
    // the last spelling is stored three times.
    const spelled = (prefixes: number): string =>
      `${"./".repeat(prefixes)}classes2.dex`;
    const crowd = join(root, "crowd.apk");
    await writeFile(
      crowd,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 60 }, (_, i) => ({
          name: spelled(i + 1),
          bytes: debuggableDex(),
        })),
        ...Array.from({ length: 3 }, () => ({
          name: spelled(61),
          bytes: debuggableDex(),
        })),
      ]),
    );
    const refused = await inspect(cli, crowd, "classes2.dex");
    expect(refused.json).toMatchObject({ code: "invalid_request" });
    const message = prose(refused.json);
    expect(message).toContain("holds 63 members named classes2.dex");
    const more =
      /, (\d+) more member\(s\) under spellings not named here\)/u.exec(
        message,
      );
    const named = message.split(String.raw`classes2.dex\"`).length - 1;
    expect(Number(more?.[1]) + named).toBe(63);
    expect(message).not.toContain(JSON.stringify(spelled(61)).slice(1, -1));
  },
);

cliTest(
  "bounds the bytes of named members and reader notes from long stored names",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-long-");
    const long = (index: number, prefixes: number): string =>
      `${"./".repeat(prefixes)}classes${index === 0 ? "" : String(index + 1)}.dex`;
    // 40 spellings of classes2.dex, each ~20 KB: ~800 KB of names before.
    const spellings = join(root, "spellings.apk");
    await writeFile(
      spellings,
      await zipArchive(
        Array.from({ length: 40 }, (_, i) => ({
          name: long(1, 10_000 + i),
          bytes: debuggableDex(),
        })),
      ),
    );
    const refused = await inspect(cli, spellings, "classes2.dex");
    expect(refused.json).toMatchObject({ code: "invalid_request" });
    expect(refused.stdout.length).toBeLessThan(16 * 1024);
    expect(refused.stdout).toContain("name shortened");
    expect(refused.stdout).toContain(
      "more member(s) under spellings not named here",
    );

    // Long non-exact canonical names: the skipped-members note stays small.
    const skipped = join(root, "skipped.apk");
    await writeFile(
      skipped,
      await zipArchive([
        { name: "classes.dex", bytes: debuggableDex() },
        ...Array.from({ length: 40 }, (_, i) => ({
          name: long(i + 1, 10_000),
          bytes: debuggableDex(),
        })),
      ]),
    );
    const summary = await inspect(cli, skipped);
    expect(summary.exitCode, summary.stdout.slice(0, 400)).toBe(0);
    expect(summary.stdout.length).toBeLessThan(64 * 1024);
    expect(summary.stdout).toContain("more canonical DEX member(s)");

    // Long Unicode Path names on every auto-loaded member: reader notes are
    // shortened, budgeted, and the rest counted.
    const noted = join(root, "noted.apk");
    await writeFile(
      noted,
      await zipArchive(
        Array.from({ length: 20 }, (_, i) => ({
          name: long(i, 0),
          bytes: debuggableDex(),
          unicodePath: `${"x".repeat(20_000)}${String(i)}.dex`,
        })),
      ),
    );
    const read = await inspect(cli, noted);
    expect(read.exitCode, read.stdout.slice(0, 400)).toBe(0);
    expect(read.stdout.length).toBeLessThan(96 * 1024);
    const limitations = evidenceOf(read.json).normalized_result.limitations;
    expect(limitations.join(" ")).toContain("note shortened");
    expect(limitations.at(-1)).toMatch(
      /^\d+ further archive-reader note\(s\) on \d+ member\(s\) read were omitted to bound the output/u,
    );
  },
);

cliTest("refuses a non-DEX file through the public CLI", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-dex-cli-bad-");
  const path = join(root, "bad.dex");
  await writeFile(path, new Uint8Array(256).fill(0x41));
  const result = await cli.run({
    arguments: ["inspect-dex-debug-metadata", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "unsupported_target",
    details: { operation: TOOL },
  });
});

cliTest(
  "answers the CLI's selection identically over stdio MCP, refuses malformed input, and keeps serving after a cancelled call",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dex-mcp-");
    const dex = join(root, "a.dex");
    await writeFile(dex, debuggableDex());
    const { call } = await connectLocalToolsMcp();

    const viaCli = await cli.run({
      arguments: ["inspect-dex-debug-metadata", dex, "--json"],
    });
    expect(viaCli.exitCode, viaCli.stderr).toBe(0);
    const viaMcp = await call(TOOL, { path: dex });
    expect(viaMcp.isError).not.toBe(true);
    expect(evidenceOf(viaMcp.structuredContent).normalized_result).toEqual(
      evidenceOf(viaCli.json).normalized_result,
    );

    const bad = join(root, "bad.dex");
    await writeFile(bad, new Uint8Array(256).fill(0x41));
    const refused = await call(TOOL, { path: bad });
    expect(refused.isError).toBe(true);
    expect(JSON.stringify(refused.content)).toContain("unsupported_target");

    const long = join(root, "long.dex");
    await writeFile(long, debuggableDex(1_500_000));
    const controller = new AbortController();
    const cancelled = call(TOOL, { path: long }, { signal: controller.signal });
    setImmediate(() => controller.abort(new Error("caller cancelled")));
    await expect(cancelled).rejects.toThrow();
    // The server settled the cancelled call and still answers.
    const after = await call(TOOL, { path: long });
    expect(after.isError).not.toBe(true);
    const result = evidenceOf(after.structuredContent).normalized_result;
    if (result.mode !== "summary") throw new Error("Expected summary");
    expect(result.members[0]?.summary.line_positions).toBe(1_500_001);
  },
);
