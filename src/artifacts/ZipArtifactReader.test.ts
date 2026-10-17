import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { crc32 } from "node:zlib";

import {
  TextReader,
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipWriter,
} from "@zip.js/zip.js";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

import { ZipArtifactReader } from "./ZipArtifactReader.js";
import {
  ARTIFACT_DECOMPRESSION_RATIO,
  artifactDecompressionBudgetBytes,
  MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
} from "../domain/artifactDecompressionBudget.js";

/** Small real ZIP carriers with forged sizes; metadata-only controls, never decompressed. */
const writeZipWithDeclaredSize = async (
  directory: string,
  declaredBytes: readonly number[],
): Promise<string> => {
  const path = join(directory, "fixture.zip");
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const [index] of declaredBytes.entries())
    await writer.add(
      `member-${index}.bin`,
      new TextReader("real member bytes"),
    );
  await writeFile(path, await writer.close());
  const bytes = await readFile(path);
  let offset = 0;
  for (const declared of declaredBytes) {
    const centralDirectory = bytes.indexOf(
      Buffer.from([0x50, 0x4b, 0x01, 0x02]),
      offset,
    );
    if (centralDirectory < 0)
      throw new Error("Expected a ZIP central directory");
    // Metadata-only controls: these declarations do not describe valid member streams.
    bytes.writeUInt32LE(declared, centralDirectory + 24);
    offset = centralDirectory + 46;
  }
  await writeFile(path, bytes);
  return path;
};

const enumerate = async (reader: ZipArtifactReader): Promise<number> => {
  let files = 0;
  for await (const entry of reader.entries())
    if (entry.kind === "file") files += 1;
  return files;
};

describe("ZipArtifactReader decompression budget", () => {
  it("refuses an archive whose entries declare more than its size can justify", async () => {
    const directory = await createTestTempDirectory("rea-zip-budget-bomb-");
    // A ~160-byte archive cannot declare 2 GiB of members without being a bomb.
    const path = await writeZipWithDeclaredSize(directory, [2_147_483_647]);
    const reader = new ZipArtifactReader(path, "zip");
    try {
      await expect(enumerate(reader)).rejects.toMatchObject({
        name: "ArtifactReaderFailure",
        reason: "limit",
      });
    } finally {
      await reader.close();
    }
  });

  it("charges all declarations in one traversal before yielding an over-budget member", async () => {
    const directory = await createTestTempDirectory("rea-zip-budget-total-");
    const half = MINIMUM_ARTIFACT_DECOMPRESSION_BYTES / 2;
    const path = await writeZipWithDeclaredSize(directory, [half, half + 1]);
    const reader = new ZipArtifactReader(path, "zip");
    const iterator = reader.entries()[Symbol.asyncIterator]();
    try {
      expect((await iterator.next()).value?.declaredSize).toBe(half);
      await expect(iterator.next()).rejects.toMatchObject({ reason: "limit" });
    } finally {
      await iterator.return?.();
      await reader.close();
    }
  });

  it("keeps repeated and interleaved metadata traversals independently charged", async () => {
    const directory = await createTestTempDirectory(
      "rea-zip-budget-iterators-",
    );
    const path = await writeZipWithDeclaredSize(directory, [
      MINIMUM_ARTIFACT_DECOMPRESSION_BYTES / 2,
      MINIMUM_ARTIFACT_DECOMPRESSION_BYTES / 2,
    ]);
    const reader = new ZipArtifactReader(path, "zip");
    const first = reader.entries()[Symbol.asyncIterator]();
    const second = reader.entries()[Symbol.asyncIterator]();
    try {
      expect((await first.next()).done).toBe(false);
      expect((await second.next()).done).toBe(false);
      expect((await first.next()).done).toBe(false);
      expect((await second.next()).done).toBe(false);
      expect((await first.next()).done).toBe(true);
      expect((await second.next()).done).toBe(true);
      expect(await enumerate(reader)).toBe(2);
    } finally {
      await Promise.all([first.return?.(), second.return?.()]);
      await reader.close();
    }
  });

  it("streams a valid small member through open", async () => {
    const directory = await createTestTempDirectory("rea-zip-budget-valid-");
    const path = join(directory, "valid.zip");
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add("member.bin", new TextReader("valid member bytes"));
    await writeFile(path, await writer.close());
    const reader = new ZipArtifactReader(path, "zip");
    try {
      const entries = [];
      for await (const entry of reader.entries()) entries.push(entry);
      const entry = entries[0];
      if (entry === undefined) throw new Error("Expected a ZIP member");
      const chunks: Buffer[] = [];
      for await (const chunk of await reader.open(entry))
        chunks.push(Buffer.from(chunk));
      expect(Buffer.concat(chunks).toString()).toBe("valid member bytes");
    } finally {
      await reader.close();
    }
  });

  it("rejects under-declared member output before delivering its complete actual bytes", async () => {
    const directory = await createTestTempDirectory("rea-zip-underdeclared-");
    const path = join(directory, "underdeclared.zip");
    const content = new Uint8Array(128 * 1024);
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add("member.bin", new Uint8ArrayReader(content), {
      dataDescriptor: false,
      bufferedWrite: true,
    });
    const bytes = Buffer.from(await writer.close());
    const local = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    const central = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    if (local < 0 || central < 0) throw new Error("Expected ZIP entry headers");
    // Both headers agree and no descriptor remains: rejection must enforce
    // actual decompressed output, not merely detect conflicting metadata.
    expect(bytes.readUInt16LE(local + 6) & 8).toBe(0);
    expect(bytes.readUInt16LE(local + 8)).toBe(8);
    expect(bytes.readUInt32LE(local + 22)).toBe(content.length);
    expect(bytes.readUInt32LE(central + 24)).toBe(content.length);
    bytes.writeUInt32LE(1, local + 22);
    bytes.writeUInt32LE(1, central + 24);
    await writeFile(path, bytes);
    const reader = new ZipArtifactReader(path, "zip");
    try {
      const entries = [];
      for await (const entry of reader.entries()) entries.push(entry);
      const entry = entries[0];
      if (entry === undefined) throw new Error("Expected a ZIP member");
      expect(entry.declaredSize).toBe(1);
      let deliveredBytes = 0;
      await expect(
        (async () => {
          for await (const chunk of await reader.open(entry))
            deliveredBytes += Buffer.from(chunk).length;
        })(),
      ).rejects.toThrow("Invalid uncompressed size");
      expect(deliveredBytes).toBeLessThan(content.length);
    } finally {
      await reader.close();
    }
  });
});

describe("ZipArtifactReader cancellation", () => {
  it("carries the caller's abort reason on enumeration and open", async () => {
    const directory = await createTestTempDirectory("rea-zip-cancel-");
    const path = join(directory, "member.zip");
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add("member.bin", new TextReader("member bytes"));
    await writeFile(path, await writer.close());
    const reader = new ZipArtifactReader(path, "zip");
    const reason = new Error("caller cancelled the ZIP read");
    try {
      const entries = [];
      for await (const entry of reader.entries()) entries.push(entry);
      const entry = entries[0];
      if (entry === undefined) throw new Error("Expected a ZIP member");
      const controller = new AbortController();
      controller.abort(reason);
      await expect(
        (async () => reader.open(entry, controller.signal))(),
      ).rejects.toMatchObject({
        reason: "cancelled",
        cancellation: { reason },
      });
      const enumeration = async () => {
        for await (const _ of reader.entries(controller.signal))
          throw new Error("Expected cancellation before a member");
      };
      await expect(enumeration()).rejects.toMatchObject({
        reason: "cancelled",
        cancellation: { reason },
      });
    } finally {
      await reader.close();
    }
  });
});

/** Info-ZIP Unicode Path extra field (0x7075) naming `unicode` for `raw`. */
const unicodePathField = (raw: string, unicode: string): Uint8Array => {
  const name = Buffer.from(unicode, "utf8");
  const field = Buffer.alloc(5 + name.length);
  field.writeUInt8(1, 0);
  field.writeUInt32LE(crc32(Buffer.from(raw, "latin1")), 1);
  name.copy(field, 5);
  return field;
};

const listEntries = async (path: string) => {
  const reader = new ZipArtifactReader(path, "zip");
  try {
    const entries = [];
    for await (const entry of reader.entries()) entries.push(entry);
    return entries;
  } finally {
    await reader.close();
  }
};

describe("ZipArtifactReader member names", () => {
  it("keeps the raw central-directory name as storedPath when a Unicode Path field renames the member", async () => {
    const directory = await createTestTempDirectory("rea-zip-unicode-path-");
    const path = join(directory, "unicode-path.zip");
    const writer = new ZipWriter(new Uint8ArrayWriter(), {
      useUnicodeFileNames: false,
    });
    await writer.add("META-INF/MANIFEST.MF", new TextReader("stored"), {
      extraField: new Map([
        [0x7075, unicodePathField("META-INF/MANIFEST.MF", "META-INF/OTHER.MF")],
      ]),
    });
    await writer.add("./plain.txt", new TextReader("plain"));
    await writeFile(path, await writer.close());

    const [renamed, prefixed] = await listEntries(path);
    // The logical path follows the Unicode Path name; a runtime that looks the
    // member up by its stored name (the JDK) still finds the manifest.
    expect(renamed).toMatchObject({
      path: "META-INF/OTHER.MF",
      storedPath: "META-INF/MANIFEST.MF",
    });
    expect(renamed?.limitations.join("\n")).toContain(
      'stored name "META-INF/MANIFEST.MF" differs from its Info-ZIP Unicode Path extra field name "META-INF/OTHER.MF"',
    );
    expect(prefixed).toMatchObject({
      path: "plain.txt",
      storedPath: "./plain.txt",
    });
  });

  it("classifies a directory only by a trailing slash and reads attribute-marked members as files", async () => {
    const directory = await createTestTempDirectory("rea-zip-dir-attributes-");
    const path = join(directory, "dir-attributes.zip");
    const writer = new ZipWriter(new Uint8ArrayWriter());
    // Unix mode 040755 and the MS-DOS directory bit (host 0) on names without
    // a trailing "/": the JDK and Python's zipfile read both as files.
    await writer.add("unix-mode", new TextReader("unix bytes"), {
      externalFileAttributes: 0o040755 * 0x10000,
    });
    await writer.add("msdos-attribute", new TextReader("msdos bytes"), {
      msDosCompatible: true,
      externalFileAttributes: 0x10,
    });
    await writer.add("real/", undefined, { directory: true });
    await writeFile(path, await writer.close());

    const reader = new ZipArtifactReader(path, "zip");
    try {
      const entries = [];
      for await (const entry of reader.entries()) entries.push(entry);
      expect(entries.map(({ path, kind }) => ({ path, kind }))).toEqual([
        { path: "unix-mode", kind: "file" },
        { path: "msdos-attribute", kind: "file" },
        { path: "real/", kind: "directory" },
      ]);
      for (const [index, expected] of [
        [0, "unix bytes"],
        [1, "msdos bytes"],
      ] as const) {
        const entry = entries[index];
        if (entry === undefined) throw new Error("Expected a ZIP member");
        expect(entry.limitations.join("\n")).toContain(
          "has directory external attributes",
        );
        const chunks: Buffer[] = [];
        for await (const chunk of await reader.open(entry))
          chunks.push(Buffer.from(chunk));
        expect(Buffer.concat(chunks).toString()).toBe(expected);
      }
    } finally {
      await reader.close();
    }
  });

  it("classifies a directory by the stored name, never by a Unicode Path name", async () => {
    const directory = await createTestTempDirectory("rea-zip-unicode-dir-");
    const path = join(directory, "unicode-dir.zip");
    const writer = new ZipWriter(new Uint8ArrayWriter(), {
      useUnicodeFileNames: false,
    });
    // Stored file "foo" (8 bytes) whose Unicode Path names "foo/", and stored
    // directory "bar/" whose Unicode Path names "bar": the JDK, Python and ART
    // read the stored names, so "foo" is a file and "bar/" a directory.
    await writer.add("foo", new TextReader("payload!"), {
      extraField: new Map([[0x7075, unicodePathField("foo", "foo/")]]),
    });
    await writer.add("bar/", undefined, {
      directory: true,
      extraField: new Map([[0x7075, unicodePathField("bar/", "bar")]]),
    });
    await writeFile(path, await writer.close());

    const reader = new ZipArtifactReader(path, "zip");
    try {
      const entries = [];
      for await (const entry of reader.entries()) entries.push(entry);
      expect(
        entries.map(({ path, kind, storedPath }) => ({
          path,
          kind,
          storedPath,
        })),
      ).toEqual([
        { path: "foo/", kind: "file", storedPath: "foo" },
        { path: "bar", kind: "directory", storedPath: "bar/" },
      ]);
      const [file] = entries;
      if (file === undefined) throw new Error("Expected a ZIP member");
      expect(file.declaredSize).toBe(8);
      // A plain file mode is not reported as directory attributes.
      expect(file.limitations.join("\n")).not.toContain(
        "directory external attributes",
      );
      const chunks: Buffer[] = [];
      for await (const chunk of await reader.open(file))
        chunks.push(Buffer.from(chunk));
      expect(Buffer.concat(chunks).toString()).toBe("payload!");
    } finally {
      await reader.close();
    }
  });
});

describe("artifactDecompressionBudgetBytes", () => {
  it("grants at least the floor and grows with the compressed size", () => {
    expect(artifactDecompressionBudgetBytes(0)).toBe(
      MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
    );
    expect(artifactDecompressionBudgetBytes(1024)).toBe(
      MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
    );
    const large = MINIMUM_ARTIFACT_DECOMPRESSION_BYTES * 4;
    expect(artifactDecompressionBudgetBytes(large)).toBe(
      large * ARTIFACT_DECOMPRESSION_RATIO,
    );
  });
});

describe("ZipArtifactReader traversal options", () => {
  const writeZip = async (names: readonly string[]): Promise<string> => {
    const path = join(
      await createTestTempDirectory("rea-zip-retain-"),
      "fixture.zip",
    );
    const writer = new ZipWriter(new Uint8ArrayWriter());
    for (const name of names)
      await writer.add(name, new Uint8ArrayReader(Buffer.from(name)));
    await writeFile(path, await writer.close());
    return path;
  };

  it("keeps only retained entries openable", async () => {
    const reader = new ZipArtifactReader(
      await writeZip(["kept.txt", "dropped.txt"]),
      "zip",
    );
    try {
      const entries = [];
      for await (const entry of reader.entries(undefined, {
        retain: (entry) => entry.path === "kept.txt",
      }))
        entries.push(entry);
      expect(entries.map((entry) => entry.path)).toEqual([
        "kept.txt",
        "dropped.txt",
      ]);
      const kept = await reader.open(entries[0]!);
      kept.destroy();
      await expect(reader.open(entries[1]!)).rejects.toMatchObject({
        reason: "integrity",
      });
    } finally {
      await reader.close();
    }
  });

  it("reports the exact stored name only when it differs from the logical path", async () => {
    const reader = new ZipArtifactReader(
      await writeZip(["./classes.dex", "classes2.dex"]),
      "zip",
    );
    try {
      const entries = [];
      for await (const entry of reader.entries()) entries.push(entry);
      expect(
        entries.map(({ path, storedPath }) => ({ path, storedPath })),
      ).toEqual([
        { path: "classes.dex", storedPath: "./classes.dex" },
        { path: "classes2.dex", storedPath: undefined },
      ]);
    } finally {
      await reader.close();
    }
  });

  it("names the bound a refused archive exceeded", async () => {
    const directory = await createTestTempDirectory("rea-zip-boundary-");
    const path = await writeZipWithDeclaredSize(directory, [
      MINIMUM_ARTIFACT_DECOMPRESSION_BYTES + 1,
    ]);
    const reader = new ZipArtifactReader(path, "zip");
    try {
      await expect(enumerate(reader)).rejects.toMatchObject({
        reason: "limit",
        boundary: "capacity",
      });
    } finally {
      await reader.close();
    }
  });
});
