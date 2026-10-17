import { createHash } from "node:crypto";
import type { FileHandle } from "node:fs/promises";
import type { Stats } from "node:fs";

import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  DexDebugMetadataExecution,
  DexDebugMetadataPort,
} from "../application/dex/DexDebugMetadataPort.js";
import { looksLikeZip, readArchiveMember } from "../artifacts/archiveMember.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import {
  bindArtifactFileCleanup,
  withArtifactRegularFile,
} from "../artifacts/ArtifactFileOperation.js";
import { hashStableRootArtifactHandle } from "../artifacts/inventory/hashStableRootArtifact.js";
import {
  peekArtifactMagic,
  readStableArtifact,
} from "../artifacts/readStableArtifact.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { dexWorkBudget } from "../domain/dex/dexDebugInfo.js";
import {
  assembleClassDetail,
  type DexClassDetail,
  type DexWork,
  summarizeDex,
} from "../domain/dex/dexDebugMetadata.js";
import {
  buildDexClassDetailResult,
  buildDexSummaryResult,
  type DexArtifactIdentity,
  type DexDebugMetadataResult,
  type DexSummaryMember,
  type InspectDexDebugMetadataInput,
} from "../domain/dex/dexDebugMetadataReport.js";
import { parseDexFile } from "../domain/dex/dexFile.js";
import { err, ok, type Result } from "../domain/result.js";
import { zipPackageFormatForPath } from "../domain/zipPackageFormat.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  completedDexEvidence,
  dexCancelled,
  DexCompletedInspection,
  dexFileFailure,
  dexReaderResource,
  DexReaderCleanupFailure,
  mapDexParseError,
  mapDexWorkError,
} from "./dexFailures.js";
import { displayName, displayNote } from "./dexDisplayText.js";
import { selectDexMembers } from "./dexMemberSelection.js";
import { DEX_LIMITS, DEX_PROVIDER_IDENTITY } from "./DexFileRelease.js";

const OPERATION = "inspect_dex_debug_metadata";

/** Let the event loop serve I/O and deliver aborts between decode slices. */
const yieldNow = (): Promise<void> =>
  new Promise((resolve) => setImmediate(resolve));

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

/**
 * A selected DEX member, read on demand. Members are loaded, analysed and
 * released one at a time, so peak memory holds one member, not all 64.
 */
interface MemberSource {
  readonly entry: string | null;
  readonly load: () => Promise<Uint8Array>;
  /** Where a parse error is reported (`path` or `path!entry`). */
  readonly label: string;
  /** What the archive reader observed about this member (e.g. its stored name). */
  readonly limitations?: readonly string[];
}

/**
 * Carries the archive reader's notes on the members read into `limitations`,
 * each shortened past its display bound and all within one byte budget; notes
 * past the budget are counted, never silently dropped.
 */
class ReaderNotes {
  #bytes = 0;
  #omitted = 0;
  readonly #omittedMembers = new Set<string>();

  constructor(readonly limitations: string[]) {}

  carry(label: string, notes: readonly string[]): void {
    for (const raw of notes) {
      const note = displayNote(raw);
      if (this.limitations.includes(note)) continue;
      const cost = Buffer.byteLength(note, "utf8");
      if (this.#bytes + cost <= DEX_LIMITS.readerNotesBytes) {
        this.#bytes += cost;
        this.limitations.push(note);
      } else {
        this.#omitted += 1;
        this.#omittedMembers.add(label);
      }
    }
  }

  /** The limitations so far, closed by the count of notes not carried. */
  facts(): string[] {
    return this.#omitted === 0
      ? this.limitations
      : [
          ...this.limitations,
          `${String(this.#omitted)} further archive-reader note(s) on ${String(this.#omittedMembers.size)} member(s) read were omitted to bound the output; inspect fewer members with entry to see them.`,
        ];
  }
}

/** Stated once, before the per-member counts of unread trailing bytes. */
const TRAILING_BYTES_NOTE =
  "Bytes after a DEX's declared file_size are never read: ART on Android 15+ ignores them, while Android 14 and earlier reject such a DEX.";

/** What one inspection keeps from its members after each is released. */
type MemberFindings = (
  | { readonly mode: "summary"; readonly members: DexSummaryMember[] }
  | {
      readonly mode: "detail";
      readonly found: {
        readonly entry: string | null;
        readonly detail: DexClassDetail;
      }[];
    }
) & {
  /** Facts about the members read that the caller must see (e.g. unread bytes). */
  readonly limitations: readonly string[];
};

const execution = (
  result: DexDebugMetadataResult,
  path: string,
  subjectSha256: string,
  format: "file" | "apk" | "zip",
): DexDebugMetadataExecution =>
  createAnalysisExecution(result, DEX_PROVIDER_IDENTITY, {
    subject: { path, format, sha256: subjectSha256 },
    locations: [{ kind: "artifact-path", path }],
    limitations: result.limitations,
  });

/** Read exactly the selected DEX bytes and report compiler-emitted debug metadata. */
export class DexFileProvider implements DexDebugMetadataPort {
  /** Owners whose close failed stay here as cleanup leases, retried by `close()`. */
  readonly #resources = new ArtifactResourceScope();

  /** Retry retained cleanup, binding a remaining failure to its exact owners. */
  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      const error = new ProviderCleanupError(
        DEX_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: OPERATION },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  async inspect(
    input: InspectDexDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<DexDebugMetadataExecution, AnalysisError>> {
    const signal = options?.signal;
    if (signal?.aborted) return err(dexCancelled(signal));
    try {
      const execution = await this.#resources.run(async () => {
        if (input.entry !== undefined)
          return this.#inspectArchive(input, signal);
        const magic = await peekArtifactMagic(
          input.path,
          8,
          signal,
          undefined,
          this.#resources,
        );
        return looksLikeZip(magic)
          ? this.#inspectArchive(input, signal)
          : this.#inspectLooseDex(input, signal);
      });
      // Observed only after the final close: keep the completed report.
      if (signal?.aborted)
        return err(
          dexCancelled(
            signal,
            undefined,
            completedDexEvidence(execution, input),
          ),
        );
      return ok(execution);
    } catch (cause: unknown) {
      return err(dexFileFailure(cause, input, signal));
    }
  }

  async #inspectLooseDex(
    input: InspectDexDebugMetadataInput,
    signal: AbortSignal | undefined,
  ): Promise<DexDebugMetadataExecution> {
    const { path } = input;
    const selected = await readStableArtifact(
      path,
      DEX_LIMITS.inputBytes,
      signal,
      undefined,
      this.#resources,
    );
    const findings = await this.#analyse(
      [
        {
          entry: null,
          load: () => Promise.resolve(selected.bytes),
          label: path,
        },
      ],
      input,
      signal,
    );
    if (!findings.ok) throw findings.error;
    return this.#assemble(findings.value, input, {
      artifact: {
        path,
        sha256: selected.sha256,
        bytes: selected.bytes.length,
      },
      container: "dex-file",
      format: "file",
    });
  }

  /**
   * Admit the archive once and keep its descriptor and ZIP reader owned
   * through the work: the reader is released after the work settles and the
   * descriptor after the reader, and a failed close is retained as a cleanup
   * lease while the work's report or primary failure is carried to the caller.
   */
  async #inspectArchive(
    input: InspectDexDebugMetadataInput,
    signal: AbortSignal | undefined,
  ): Promise<DexDebugMetadataExecution> {
    const { path } = input;
    const completed = await withArtifactRegularFile(
      path,
      this.#resources,
      signal,
      async (handle) => {
        const initial = await handle.stat();
        if (initial.size > DEX_LIMITS.archiveBytes)
          throw new AnalysisResourceConstraintError(
            OPERATION,
            "file-size",
            `Selected archive exceeds ${String(DEX_LIMITS.archiveBytes)} bytes: ${path}`,
            { maximum_archive_bytes: DEX_LIMITS.archiveBytes },
          );
        const zipFormat = zipPackageFormatForPath(path) ?? "zip";
        const reader = new ZipArtifactReader(
          path,
          zipFormat,
          DEX_LIMITS.archiveMetadataBytes,
          { handle, initial },
        );
        const lease = new AnalysisCleanupLease(() => reader.close());
        let outcome: DexReaderCleanupFailure["outcome"];
        try {
          outcome = {
            kind: "completed",
            value: new DexCompletedInspection(
              await this.#readArchive(reader, input, signal, {
                handle,
                initial,
                format: zipFormat === "apk" ? "apk" : "zip",
              }),
            ),
          };
        } catch (cause: unknown) {
          outcome = { kind: "failed", cause };
        }
        const released = await this.#resources.release({
          kind: "lease",
          resource: dexReaderResource(path),
          lease,
        });
        if (released.kind === "failed")
          throw new DexReaderCleanupFailure(
            path,
            outcome,
            released.cause,
            lease,
          );
        if (outcome.kind === "failed") throw outcome.cause;
        return outcome.value;
      },
    );
    return completed.execution;
  }

  async #readArchive(
    reader: ZipArtifactReader,
    input: InspectDexDebugMetadataInput,
    signal: AbortSignal | undefined,
    archive: {
      readonly handle: FileHandle;
      readonly initial: Stats;
      readonly format: "apk" | "zip";
    },
  ): Promise<DexDebugMetadataExecution> {
    const { path } = input;
    const selected = await selectDexMembers(reader, input.entry, path, signal);
    if (!selected.ok) throw selected.error;
    const findings = await this.#analyse(
      selected.value.members.map(({ entry, member }) => ({
        entry,
        label: `${path}!${displayName(entry)}`,
        limitations: member.limitations,
        load: () =>
          readArchiveMember(reader, member, DEX_LIMITS.inputBytes, signal),
      })),
      input,
      signal,
      selected.value.skippedNote === undefined
        ? []
        : [selected.value.skippedNote],
    );
    if (!findings.ok) throw findings.error;
    const digest = await hashStableRootArtifactHandle(
      path,
      archive.handle,
      archive.initial,
      signal,
    );
    return this.#assemble(findings.value, input, {
      artifact: { path, sha256: digest.sha256, bytes: digest.bytes },
      container: archive.format,
      format: archive.format,
    });
  }

  /**
   * Load, frame and analyse each member in turn, each under a work budget
   * proportional to its own bytes, keeping only its summary or matching class
   * detail before the next member is read.
   */
  async #analyse(
    sources: readonly MemberSource[],
    input: InspectDexDebugMetadataInput,
    signal: AbortSignal | undefined,
    selectionFacts: readonly string[] = [],
  ): Promise<Result<MemberFindings, AnalysisError>> {
    const cancelled = (): boolean => signal?.aborted === true;
    const summaries: DexSummaryMember[] = [];
    const found: { entry: string | null; detail: DexClassDetail }[] = [];
    const limitations: string[] = [...selectionFacts];
    const notes = new ReaderNotes(limitations);
    for (const source of sources) {
      if (signal?.aborted) return err(dexCancelled(signal));
      const loaded = await source.load();
      notes.carry(source.label, source.limitations ?? []);
      const parsed = parseDexFile(loaded);
      if (!parsed.ok)
        return err(mapDexParseError(parsed.error, source.label, notes.facts()));
      // Analysis reads only the bytes the header frames; identity (SHA-256,
      // size) stays over the selected bytes.
      const buffer = parsed.value.framed;
      if (parsed.value.trailingBytes > 0) {
        if (!limitations.includes(TRAILING_BYTES_NOTE))
          limitations.push(TRAILING_BYTES_NOTE);
        limitations.push(
          `${source.label} has ${String(parsed.value.trailingBytes)} bytes after its declared file_size; they were not read.`,
        );
      }
      const work: DexWork = {
        budget: dexWorkBudget(
          Math.max(
            DEX_LIMITS.minWorkUnits,
            DEX_LIMITS.workUnitsPerByte * buffer.length,
          ),
        ),
        cancelled,
        yieldNow,
        sliceUnits: DEX_LIMITS.workUnitsPerSlice,
      };
      if (input.class_descriptor === undefined) {
        const summary = await summarizeDex(parsed.value, buffer, work);
        if (!summary.ok)
          return err(
            mapDexWorkError(summary.error, source.label, notes.facts(), signal),
          );
        summaries.push({
          entry: source.entry,
          sha256: sha256(loaded),
          bytes: loaded.length,
          summary: summary.value,
        });
        continue;
      }
      const detail = await assembleClassDetail(
        parsed.value,
        buffer,
        input.class_descriptor,
        work,
        DEX_LIMITS.outputBytes,
      );
      if (!detail.ok)
        return err(
          mapDexWorkError(detail.error, source.label, notes.facts(), signal),
        );
      if (detail.value !== null)
        found.push({ entry: source.entry, detail: detail.value });
      // A second match is already ambiguous; reading further members is waste.
      if (found.length > 1) break;
    }
    const facts = notes.facts();
    return ok(
      input.class_descriptor === undefined
        ? { mode: "summary", members: summaries, limitations: facts }
        : { mode: "detail", found, limitations: facts },
    );
  }

  /** Decide summary vs class-detail over the decoded members and build the result. */
  #assemble(
    findings: MemberFindings,
    input: InspectDexDebugMetadataInput,
    context: {
      readonly artifact: DexArtifactIdentity;
      readonly container: DexDebugMetadataResult["container"];
      readonly format: "file" | "apk" | "zip";
    },
  ): DexDebugMetadataExecution {
    const { artifact, container, format } = context;
    const result: Result<DexDebugMetadataResult, AnalysisError> =
      findings.mode === "summary"
        ? ok(buildDexSummaryResult(artifact, container, findings.members))
        : this.#classDetail(
            findings.found,
            input.class_descriptor ?? "",
            artifact,
            container,
            findings.limitations,
          );
    if (!result.ok) throw result.error;
    const report = {
      ...result.value,
      limitations: [...result.value.limitations, ...findings.limitations],
    };
    const tooLarge = this.#rejectIfOversized(
      report,
      artifact.path,
      findings.limitations,
    );
    if (tooLarge) throw tooLarge;
    return execution(report, artifact.path, artifact.sha256, format);
  }

  #classDetail(
    found: readonly {
      readonly entry: string | null;
      readonly detail: DexClassDetail;
    }[],
    descriptor: string,
    artifact: DexArtifactIdentity,
    container: DexDebugMetadataResult["container"],
    limitations: readonly string[],
  ): Result<DexDebugMetadataResult, AnalysisError> {
    // Facts about what was (not) read must reach the caller on refusals too.
    const context = limitations.length === 0 ? "" : ` ${limitations.join(" ")}`;
    if (found.length === 0)
      return err(
        this.#inputError(
          "class_descriptor",
          `No class ${descriptor} exists in the selected DEX member(s).${context}`,
        ),
      );
    if (found.length > 1)
      return err(
        this.#inputError(
          "class_descriptor",
          `Class ${descriptor} appears in more than one dex member; select one with entry.${context}`,
        ),
      );
    return ok(
      buildDexClassDetailResult(artifact, container, found[0]!, descriptor),
    );
  }

  #rejectIfOversized(
    result: DexDebugMetadataResult,
    path: string,
    limitations: readonly string[],
  ): AnalysisResourceConstraintError | undefined {
    // The Evidence envelope repeats `limitations` beside the result, so both
    // copies are emitted and both are counted.
    if (
      Buffer.byteLength(JSON.stringify(result), "utf8") +
        Buffer.byteLength(JSON.stringify(result.limitations), "utf8") <=
      DEX_LIMITS.outputBytes
    )
      return undefined;
    return new AnalysisResourceConstraintError(
      OPERATION,
      "transport",
      `Decoded DEX detail for ${path} exceeds the inline output budget; select a narrower class.${limitations.length === 0 ? "" : ` ${limitations.join(" ")}`}`,
      { maximum_output_bytes: DEX_LIMITS.outputBytes },
    );
  }

  #inputError(
    field: "entry" | "class_descriptor",
    message: string,
  ): AnalysisInputError {
    return new AnalysisInputError(OPERATION, undefined, [
      { path: [field], reason: "invalid_value", message },
    ]);
  }
}
