import { describe, expect, it } from "vitest";

import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { DEX_LIMITS } from "./DexFileRelease.js";
import { dexFileFailure, mapDexWorkError } from "./dexFailures.js";

describe("mapDexWorkError", () => {
  it("names the member and carries facts about the bytes read on every refusal", () => {
    const fact =
      "x.dex has 5 bytes after its declared file_size; they were not read.";
    for (const error of [
      { kind: "work-budget-exceeded", limit: 10 },
      { kind: "duplicate-class-definition", count: 2 },
      { kind: "unreadable-class-identity", count: 1 },
      { kind: "malformed-class-data", classDataOff: 64 },
      { kind: "output-budget-exceeded", projectedBytes: 9, limit: 8 },
    ] as const) {
      const mapped = mapDexWorkError(error, "app.apk!classes2.dex", [fact]);
      const text = JSON.stringify(mapped) + mapped.message;
      expect(text).toContain("5 bytes after");
      expect(text).toContain("app.apk!classes2.dex");
      expect(JSON.stringify(mapDexWorkError(error, "x.dex"))).not.toContain(
        "bytes after",
      );
    }
  });
});

describe("dexFileFailure", () => {
  const input = { path: "/a/app.apk" };

  it("reports each size limit with its own maximum", () => {
    const limits = (boundary?: "memory" | "capacity" | "file-size") =>
      projectAnalysisError(
        dexFileFailure(
          new ArtifactReaderFailure(
            "limit",
            "over",
            boundary === undefined ? undefined : { boundary },
          ),
          input,
        ),
      ).details;
    expect(JSON.stringify(limits("memory"))).toContain(
      `"maximum_archive_metadata_read_bytes":${String(DEX_LIMITS.archiveMetadataBytes)}`,
    );
    expect(JSON.stringify(limits("capacity"))).toContain(
      '"decompression_ratio":500',
    );
    expect(JSON.stringify(limits("file-size"))).toContain(
      `"max_input_bytes":${String(DEX_LIMITS.inputBytes)}`,
    );
    expect(JSON.stringify(limits("memory"))).not.toContain("max_input_bytes");
  });

  it("blames malformed input on the caller but I/O on the adapter", () => {
    expect(
      dexFileFailure(new ArtifactReaderFailure("format", "bad zip"), input),
    ).toBeInstanceOf(AnalysisInputError);
    for (const reason of ["io", "unavailable"] as const)
      expect(
        dexFileFailure(new ArtifactReaderFailure(reason, "eio"), input),
      ).toBeInstanceOf(ProviderAdapterError);
  });

  it("carries the caller's abort reason on every cancellation", () => {
    const controller = new AbortController();
    const reason = new Error("stop");
    controller.abort(reason);
    expect(
      dexFileFailure(
        new ArtifactReaderFailure("cancelled", "read cancelled"),
        input,
        controller.signal,
      ).cause,
    ).toBe(reason);
    expect(
      mapDexWorkError({ kind: "cancelled" }, "x.dex", [], controller.signal)
        .cause,
    ).toBe(reason);
  });

  it("points malformed-structure refusals at the selected artifact", () => {
    for (const error of [
      { kind: "duplicate-class-definition", count: 2 },
      { kind: "unreadable-class-identity", count: 1 },
      { kind: "malformed-class-data", classDataOff: 64 },
    ] as const)
      expect(
        (mapDexWorkError(error, "x.dex") as AnalysisInputError).issues[0]?.path,
      ).toEqual(["path"]);
  });
});
