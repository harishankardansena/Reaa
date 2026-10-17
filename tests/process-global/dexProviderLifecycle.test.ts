import { writeFile, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * DEX provider lifecycle: the selected descriptor (loose `.dex`, or the APK's
 * admitted descriptor) and the archive's ZIP reader are owned through the
 * work, released after it settles, retained as cleanup leases when a close
 * fails, and retried by `close()`. Faults are injected at the real
 * `node:fs/promises` handle and at the ZIP reader's close.
 */
const fault = vi.hoisted(() => ({
  path: "",
  /** Which opened handle of `path` (0-based) fails its close; -1 for none. */
  failIndex: -1,
  opened: 0,
  denied: true,
  handles: [] as FileHandle[],
  onClose: undefined as (() => void) | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...original,
    open: async (...arguments_: Parameters<typeof original.open>) => {
      const handle = await original.open(...arguments_);
      if (String(arguments_[0]) !== fault.path) return handle;
      const index = fault.opened++;
      fault.handles.push(handle);
      const close = handle.close.bind(handle);
      handle.close = async () => {
        fault.onClose?.();
        if (index === fault.failIndex && fault.denied)
          throw new Error("controlled DEX descriptor close failure");
        await close();
      };
      return handle;
    },
  };
});

import { ZipArtifactReader } from "../../src/artifacts/ZipArtifactReader.js";
import { DexFileProvider } from "../../src/dex/DexFileProvider.js";
import { AnalysisCancelledError } from "../../src/domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../src/domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../src/domain/providerCleanupError.js";
import { debuggableDex, zipArchive } from "../fixtures/dexFile.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

beforeEach(() => {
  fault.path = "";
  fault.failIndex = -1;
  fault.opened = 0;
  fault.denied = true;
  fault.handles = [];
  fault.onClose = undefined;
});
afterEach(() => {
  vi.restoreAllMocks();
});

const looseDex = async (): Promise<string> => {
  const path = join(await createTestTempDirectory("rea-dex-life-"), "a.dex");
  await writeFile(path, debuggableDex());
  return path;
};
const apk = async (): Promise<string> => {
  const path = join(await createTestTempDirectory("rea-dex-life-"), "a.apk");
  await writeFile(
    path,
    await zipArchive([{ name: "classes.dex", bytes: debuggableDex() }]),
  );
  return path;
};

/**
 * Each target and the opened handle that performs its work: a loose file and
 * an APK summary are first peeked (handle 0), an APK `entry` selection is not.
 */
const targets = [
  ["loose .dex", looseDex, {}, 1],
  ["APK summary", apk, {}, 1],
  ["APK entry", apk, { entry: "classes.dex" }, 0],
] as const;

describe.each(targets)("DEX %s lifecycle", (_name, make, extra, workHandle) => {
  it("retains a failed descriptor close, then clears it once close() releases it", async () => {
    const path = await make();
    const provider = new DexFileProvider();
    fault.path = path;
    fault.failIndex = workHandle;
    const result = await provider.inspect({ path, ...extra });
    if (result.ok) throw new Error("Expected incomplete cleanup");
    expect(result.error.cleanupIncomplete).toBe(true);
    expect(result.error.cleanupResources).toContain(path);
    // A completed APK report survives its descriptor's failed close; a loose
    // read whose descriptor failed to close is an execution failure.
    if (_name === "loose .dex") {
      expect(result.error).toBeInstanceOf(ProviderAdapterError);
      expect(result.error.partialObservation).toBeUndefined();
    } else {
      expect(result.error).toBeInstanceOf(ProviderCleanupError);
      expect(result.error.partialObservation).toMatchObject({
        operation: "inspect_dex_debug_metadata",
        normalized_result: { mode: "summary" },
      });
    }
    // The first retry still fails and is bound to the same owner.
    const first = await provider.close().then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(first).toBeInstanceOf(ProviderCleanupError);
    expect((first as ProviderCleanupError).cleanupIncomplete).toBe(true);
    fault.denied = false;
    await provider.close();
    expect(result.error.cleanupIncomplete).toBe(false);
    expect((first as ProviderCleanupError).cleanupIncomplete).toBe(false);
    expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
  });

  it("returns typed cancellation with the abort reason when it arrives during the final close", async () => {
    const path = await make();
    const provider = new DexFileProvider();
    const controller = new AbortController();
    const reason = new Error("cancel during the final descriptor close");
    fault.path = path;
    fault.onClose = () => {
      if (fault.handles.length > workHandle) controller.abort(reason);
    };
    try {
      const result = await provider.inspect(
        { path, ...extra },
        { signal: controller.signal },
      );
      if (result.ok) throw new Error("Expected late cancellation");
      expect(result.error).toBeInstanceOf(AnalysisCancelledError);
      expect(result.error.cause).toBe(reason);
      expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
    } finally {
      await provider.close();
    }
  });

  it("keeps the cancellation and binds the failed close when both happen at the end", async () => {
    const path = await make();
    const provider = new DexFileProvider();
    const controller = new AbortController();
    const reason = new Error("cancel while the close fails");
    fault.path = path;
    fault.failIndex = workHandle;
    fault.onClose = () => {
      if (fault.handles.length > workHandle) controller.abort(reason);
    };
    const result = await provider.inspect(
      { path, ...extra },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation with cleanup");
    const projected = result.error.cause as AggregateError;
    expect(projected.errors[0]).toBeInstanceOf(AnalysisCancelledError);
    expect((projected.errors[0] as Error).cause).toBe(reason);
    expect(result.error.cleanupIncomplete).toBe(true);
    fault.denied = false;
    await provider.close();
    expect(result.error.cleanupIncomplete).toBe(false);
  });
});

describe("DEX archive ZIP reader lifecycle", () => {
  it("reports a failed reader close by its owner, keeps the report, and retries it in close()", async () => {
    const path = await apk();
    const provider = new DexFileProvider();
    const original = ZipArtifactReader.prototype.close;
    let denied = true;
    vi.spyOn(ZipArtifactReader.prototype, "close").mockImplementation(
      async function (this: ZipArtifactReader) {
        if (denied) throw new Error("controlled ZIP reader close failure");
        await original.call(this);
      },
    );
    const result = await provider.inspect({ path });
    if (result.ok) throw new Error("Expected incomplete reader cleanup");
    expect(result.error).toBeInstanceOf(ProviderCleanupError);
    expect(result.error.cleanupResources).toEqual([`${path} (ZIP reader)`]);
    expect(result.error.partialObservation).toMatchObject({
      normalized_result: { container: "apk", mode: "summary" },
    });
    // The descriptor itself was still released.
    expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
    // Admission stays blocked behind the retained reader.
    const blocked = await provider.inspect({ path });
    expect(blocked.ok).toBe(false);
    denied = false;
    await provider.close();
    expect(result.error.cleanupIncomplete).toBe(false);
    await provider.close();
  });

  it("keeps the work's primary failure when the reader close also fails", async () => {
    const dir = await createTestTempDirectory("rea-dex-life-");
    const path = join(dir, "bad.apk");
    await writeFile(
      path,
      await zipArchive([
        { name: "classes.dex", bytes: new Uint8Array(256).fill(0x41) },
      ]),
    );
    const provider = new DexFileProvider();
    const original = ZipArtifactReader.prototype.close;
    let denied = true;
    vi.spyOn(ZipArtifactReader.prototype, "close").mockImplementation(
      async function (this: ZipArtifactReader) {
        if (denied) throw new Error("controlled ZIP reader close failure");
        await original.call(this);
      },
    );
    const result = await provider.inspect({ path });
    if (result.ok) throw new Error("Expected a primary failure");
    const aggregate = result.error.cause as AggregateError;
    expect(aggregate.errors[0]).toMatchObject({
      _tag: "AnalysisUnsupportedTargetError",
    });
    expect(result.error.cleanupResources).toEqual([`${path} (ZIP reader)`]);
    denied = false;
    await provider.close();
    expect(result.error.cleanupIncomplete).toBe(false);
  });
});
