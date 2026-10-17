import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { DexDebugMetadataService } from "./DexDebugMetadataService.js";
import { DexFileProvider } from "../../dex/DexFileProvider.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { debuggableDex } from "../../../tests/fixtures/dexFile.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

it("keeps a validated report as Evidence when cancellation arrives as the provider returns", async () => {
  const path = join(await createTestTempDirectory("rea-dex-svc-"), "a.dex");
  await writeFile(path, debuggableDex());
  const controller = new AbortController();
  const reason = new Error("cancel as the report reaches the workflow");
  const provider = new DexFileProvider();
  const service = new DexDebugMetadataService({
    close: () => provider.close(),
    inspect: async (input, options) => {
      const result = await provider.inspect(input, options);
      controller.abort(reason);
      return result;
    },
  });
  try {
    const result = await service.inspect(
      { path },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected late cancellation");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(result.error.cause).toBe(reason);
    expect(result.error.partialObservation).toMatchObject({
      operation: "inspect_dex_debug_metadata",
      normalized_result: { container: "dex-file", mode: "summary" },
    });
  } finally {
    await service.close();
  }
});

it("carries the abort reason when cancelled before admission", async () => {
  const controller = new AbortController();
  const reason = new Error("cancelled early");
  controller.abort(reason);
  const service = new DexDebugMetadataService(new DexFileProvider());
  const result = await service.inspect(
    { path: "/nonexistent.dex" },
    { signal: controller.signal },
  );
  expect(result.ok || result.error.cause).toBe(reason);
});
