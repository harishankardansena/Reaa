import type { DexDebugMetadataExecution } from "../application/dex/DexDebugMetadataPort.js";
import {
  AnalysisCleanupLease,
  AnalysisCleanupLeaseGroup,
} from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  ArtifactFileCancelled,
  ArtifactFileCleanupFailure,
  artifactFileCancellationCause,
  bindArtifactFileCleanup,
} from "../artifacts/ArtifactFileOperation.js";
import type { AnalysisCleanupObservation } from "../domain/analysisErrorBase.js";
import {
  ARTIFACT_DECOMPRESSION_RATIO,
  MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
} from "../domain/artifactDecompressionBudget.js";
import type { InspectDexDebugMetadataInput } from "../domain/dex/dexDebugMetadataReport.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { DexWorkError } from "../domain/dex/dexDebugMetadata.js";
import type { DexFileParseError } from "../domain/dex/dexFile.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { DEX_LIMITS, DEX_PROVIDER_IDENTITY } from "./DexFileRelease.js";

const OPERATION = "inspect_dex_debug_metadata";

const inputError = (
  reason: "invalid_format" | "invalid_value",
  message: string,
): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path: ["path"], reason, message },
  ]);

/**
 * Map a tagged DEX parse failure to the shared analysis error algebra. `path`
 * names the member (`archive!entry` inside an APK/ZIP); `limitations` are facts
 * about members already read that the refusal must still carry.
 */
export const mapDexParseError = (
  error: DexFileParseError,
  path: string,
  limitations: readonly string[] = [],
): AnalysisError => {
  const context = limitations.length === 0 ? "" : ` ${limitations.join(" ")}`;
  switch (error.kind) {
    case "bad-magic":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `${path} does not begin with the DEX magic (dex\\n0NN).${context}`,
        {
          remediationAction:
            "Select a .dex file, or pass entry to select a classesN.dex inside an APK/ZIP.",
        },
      );
    case "compact-dex":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `${path} is a compact dex (cdex) extracted from a vdex; it is a device-optimized format.${context}`,
        {
          remediationAction:
            "Provide a canonical .dex (e.g. from the APK), not an on-device odex/vdex/cdex.",
        },
      );
    case "reverse-endian":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `${path} declares the reverse-endian tag, which ART itself rejects; it is not read.${context}`,
      );
    case "unsupported-version":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `${path}: DEX format version ${error.version} is not supported (reads 035, 037-040).${context}`,
      );
    case "bad-header":
      return inputError(
        "invalid_format",
        `${path}: malformed DEX header: ${error.detail}.${context}`,
      );
    case "truncated":
      return inputError(
        "invalid_format",
        `${path}: DEX ended before a structure completed at byte ${String(error.offset)}.${context}`,
      );
    case "budget-exceeded":
      return inputError(
        "invalid_value",
        `${path}: declared ${error.resource} count (${String(error.declared)}) exceeds the remaining ${String(error.remaining)} bytes at byte ${String(error.offset)}.${context}`,
      );
    case "member-index-exceeds-ids":
      return inputError(
        "invalid_value",
        `${path}: class_data entry at byte ${String(error.offset)} names ${error.members} index ${String(error.index)}, past the ${String(error.bound)} ids the DEX defines.${context}`,
      );
    case "invalid-index":
      return inputError(
        "invalid_value",
        `${path}: DEX offset ${String(error.index)} is outside the file bound ${String(error.bound)}.${context}`,
      );
  }
};

/**
 * An inspection whose report completed inside an owned descriptor operation.
 * Wrapping it lets a later cleanup failure or cancellation retain the report
 * as a partial observation without mistaking another completed read (a magic
 * peek, the loose-file bytes) for a report.
 */
export class DexCompletedInspection {
  constructor(readonly execution: DexDebugMetadataExecution) {}
}

/** The archive's ZIP reader failed to close after the archive work settled. */
export class DexReaderCleanupFailure extends Error {
  constructor(
    readonly path: string,
    /** The settled archive work: its completed report or its primary failure. */
    readonly outcome:
      | { readonly kind: "completed"; readonly value: DexCompletedInspection }
      | { readonly kind: "failed"; readonly cause: unknown },
    readonly cleanupCause: unknown,
    readonly cleanupLease: AnalysisCleanupLease,
  ) {
    super(`ZIP reader cleanup failed for ${path}`, { cause: cleanupCause });
    this.name = "DexReaderCleanupFailure";
  }
}

/** The resource name a retained ZIP reader is reported under. */
export const dexReaderResource = (path: string): string =>
  `${path} (ZIP reader)`;

/** Evidence for a report that completed before cancellation or failed cleanup. */
export const completedDexEvidence = (
  execution: DexDebugMetadataExecution,
  input: InspectDexDebugMetadataInput,
): Evidence =>
  createEvidence(execution.subject, execution.provider, {
    operation: OPERATION,
    parameters: {
      path: input.path,
      ...(input.entry === undefined ? {} : { entry: input.entry }),
      ...(input.class_descriptor === undefined
        ? {}
        : { class_descriptor: input.class_descriptor }),
    },
    result: execution.result,
    confidence: "observed",
    locations: execution.locations,
    limitations: execution.limitations,
  });

/** Cancellation always carries the caller's abort reason as its cause. */
export const dexCancelled = (
  signal: AbortSignal | undefined,
  fallbackCause?: unknown,
  partialObservation?: Evidence,
): AnalysisCancelledError =>
  new AnalysisCancelledError(OPERATION, {
    cause: signal?.aborted === true ? signal.reason : fallbackCause,
    ...(partialObservation === undefined ? {} : { partialObservation }),
  });

const messageOf = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/** The owned cleanup layers of a failure, down to the work's own outcome. */
interface CleanupLayers {
  readonly cleanups: readonly AnalysisCleanupObservation[];
  /** Exact owners to bind, or undefined when one is not a known lease. */
  readonly leases: readonly AnalysisCleanupLease[] | undefined;
  /** The work's failure, when it did not complete. */
  readonly failure: unknown;
  /** The work's completed value, when it did. */
  readonly completed: unknown;
}

const unwindCleanup = (cause: unknown): CleanupLayers => {
  const cleanups: AnalysisCleanupObservation[] = [];
  let leases: AnalysisCleanupLease[] | undefined = [];
  let current = cause;
  for (;;) {
    let outcome:
      | { readonly kind: "completed"; readonly value: unknown }
      | { readonly kind: "failed"; readonly cause: unknown };
    if (current instanceof ArtifactFileCleanupFailure) {
      const physical = current.fileCleanupFailure;
      cleanups.push(
        ArtifactReaderFailure.cleanupObservation(
          physical.cleanupCause,
          physical.path,
        ),
      );
      leases =
        leases === undefined || current.cleanupLeases === undefined
          ? undefined
          : [...leases, ...current.cleanupLeases];
      outcome = physical.outcome;
    } else if (current instanceof DexReaderCleanupFailure) {
      cleanups.push({
        reason: messageOf(current.cleanupCause),
        resources: [dexReaderResource(current.path)],
      });
      leases =
        leases === undefined ? undefined : [...leases, current.cleanupLease];
      outcome = current.outcome;
    } else if (current instanceof ArtifactFileCancelled)
      // Cancelled after the descriptor closed: the physical work completed.
      outcome = current.fileCancellation.outcome;
    else return { cleanups, leases, failure: current, completed: undefined };
    if (outcome.kind === "completed")
      return { cleanups, leases, failure: undefined, completed: outcome.value };
    current = outcome.cause;
  }
};

/**
 * Translate a provider failure, walking the owned cleanup layers (descriptor
 * close, ZIP reader close) down to the work's own outcome. The work's primary
 * failure (or completed report) is kept, every failed close is reported by the
 * exact owner it names, and the returned error is bound to those owners'
 * cleanup leases so a confirmed `close()` retry resolves it.
 */
export const dexFileFailure = (
  cause: unknown,
  input: InspectDexDebugMetadataInput,
  signal?: AbortSignal,
): AnalysisError => {
  const { cleanups, leases, failure, completed } = unwindCleanup(cause);
  const report =
    completed instanceof DexCompletedInspection
      ? completedDexEvidence(completed.execution, input)
      : undefined;
  const cleanedUp = cleanups.length === 0;
  // Which failure the caller sees first: the work's own failure, a
  // cancellation observed after it settled, or (a completed read whose close
  // failed) an execution failure, as for any other one-shot reader.
  const primary: AnalysisError | undefined =
    completed === undefined
      ? primaryFileFailure(failure, input.path, signal)
      : signal?.aborted === true
        ? dexCancelled(signal, undefined, report)
        : report !== undefined
          ? undefined
          : cleanedUp
            ? dexCancelled(signal, cause)
            : new ProviderAdapterError(DEX_PROVIDER_IDENTITY.id, OPERATION, {
                cause,
                diagnostics: {
                  path: input.path,
                  reason: cleanups.map(({ reason }) => reason).join("; "),
                },
              });
  if (cleanedUp) {
    const error = primary ?? dexCancelled(signal, cause, report);
    bindArtifactFileCleanup(cause, error);
    return error;
  }
  const cleanup = new ProviderCleanupError(
    DEX_PROVIDER_IDENTITY.id,
    [...new Set(cleanups.flatMap(({ resources }) => resources))],
    { reason: cleanups.map(({ reason }) => reason).join("; ") },
    {
      operation: OPERATION,
      cause,
      ...(report === undefined ? {} : { partialObservation: report }),
    },
  );
  const error =
    primary === undefined
      ? cleanup
      : analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
  if (leases !== undefined) new AnalysisCleanupLeaseGroup(error, leases);
  return error;
};

/** Size limits by the bound the reader names; each reports its own maximum. */
const limitFailure = (
  cause: ArtifactReaderFailure,
  options: {
    readonly cause: unknown;
    readonly cleanup?: AnalysisCleanupObservation;
  },
): AnalysisError => {
  switch (cause.boundary) {
    case "memory":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        cause.message,
        {
          maximum_archive_metadata_read_bytes: DEX_LIMITS.archiveMetadataBytes,
        },
        {
          ...options,
          remediationAction:
            "The archive metadata budget is fixed; extract the DEX member and select it directly.",
        },
      );
    case "capacity":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        cause.message,
        {
          decompression_ratio: ARTIFACT_DECOMPRESSION_RATIO,
          minimum_decompression_budget_bytes:
            MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
        },
        {
          ...options,
          remediationAction:
            "The decompression budget scales with the archive size; extract the DEX member and select it directly.",
        },
      );
    default:
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { max_input_bytes: DEX_LIMITS.inputBytes },
        {
          ...options,
          remediationAction:
            "The DEX size budget is fixed; select a smaller artifact.",
        },
      );
  }
};

/** A typed reader failure: cancellation, limit, change, or the artifact's form. */
const readerFailure = (
  cause: ArtifactReaderFailure,
  path: string,
  signal: AbortSignal | undefined,
): AnalysisError => {
  const options = {
    cause,
    ...(cause.cleanup === undefined ? {} : { cleanup: cause.cleanup }),
  };
  switch (cause.reason) {
    case "cancelled":
      return new AnalysisCancelledError(OPERATION, {
        ...options,
        cause:
          signal?.aborted === true
            ? signal.reason
            : artifactFileCancellationCause(cause),
      });
    case "limit":
      return limitFailure(cause, options);
    case "integrity":
      return new AnalysisArtifactChangedError(
        OPERATION,
        path,
        cause.message,
        options,
      );
    // A malformed container or a non-regular path describes the selected
    // artifact, so it stays a caller-facing input error.
    case "format":
    case "path":
      return new AnalysisInputError(OPERATION, options, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
    // I/O and unavailable resources (including retained cleanup that still
    // cannot close) are adapter failures, never blamed on the input.
    case "io":
    case "unavailable":
      return new ProviderAdapterError(DEX_PROVIDER_IDENTITY.id, OPERATION, {
        ...options,
        diagnostics: { path, reason: cause.message },
      });
  }
};

const primaryFileFailure = (
  cause: unknown,
  path: string,
  signal: AbortSignal | undefined,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof ArtifactReaderFailure)
    return readerFailure(cause, path, signal);
  const code =
    cause instanceof Error && "code" in cause ? String(cause.code) : undefined;
  if (cause instanceof Error && cause.name === "AbortError")
    return new AnalysisCancelledError(OPERATION, {
      cause: signal?.aborted === true ? signal.reason : cause,
    });
  if (code === "EACCES" || code === "EPERM")
    return new AnalysisAccessDeniedError(OPERATION, path, code, { cause });
  if (code === "ENOENT" || code === "ENOTDIR" || code === "ELOOP")
    return new AnalysisInputError(OPERATION, { cause }, [
      {
        path: ["path"],
        reason: "invalid_value",
        message: `No regular file can be read at the selected path (${code}): ${path}.`,
      },
    ]);
  // Anything untyped (e.g. a RangeError) is an adapter defect.
  return new ProviderAdapterError(DEX_PROVIDER_IDENTITY.id, OPERATION, {
    cause,
    diagnostics: { path, reason: messageOf(cause) },
  });
};

/**
 * Map a refused summary/detail to the shared error algebra. `limitations` are
 * facts about the members already read (e.g. unread trailing bytes) that a
 * refusal must still carry.
 */
export const mapDexWorkError = (
  error: DexWorkError,
  label: string,
  limitations: readonly string[] = [],
  signal?: AbortSignal,
): AnalysisError => {
  const context = limitations.length === 0 ? "" : ` ${limitations.join(" ")}`;
  switch (error.kind) {
    case "cancelled":
      return dexCancelled(signal);
    case "work-budget-exceeded":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "cpu",
        `Decoding the debug metadata of ${label} needs more than ${String(error.limit)} work units (proportional to its size); a well-formed DEX never does, so it was refused rather than run unbounded.${context}`,
        { max_work_units: error.limit },
      );
    case "malformed-class-data":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `${label}: the selected class's class_data at byte ${String(error.classDataOff)} cannot be read; its methods' debug metadata is unknown.${context}`,
        },
      ]);
    case "unreadable-class-identity":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `${label}: ${String(error.count)} class_def entr${error.count === 1 ? "y has" : "ies have"} an unreadable type identity, so whether this DEX member defines the class (once) is unknown, not absent.${context}`,
        },
      ]);
    case "duplicate-class-definition":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `${label}: ${String(error.count)} class_def entries declare the class in one DEX member; the DEX is malformed and the definition is ambiguous.${context}`,
        },
      ]);
    case "output-budget-exceeded":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `${label}: the class detail would serialise to about ${String(error.projectedBytes)} bytes, over the ${String(error.limit)}-byte output budget; refused before building it.${context}`,
        { maximum_output_bytes: error.limit },
      );
  }
};
