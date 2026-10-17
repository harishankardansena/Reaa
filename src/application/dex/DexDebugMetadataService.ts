import { isAbsolute } from "node:path";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { DexDebugMetadataPort } from "./DexDebugMetadataPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  dexDebugMetadataMatchesSubject,
  dexReportMatchesSelection,
  dexDebugMetadataResultSchema,
  inspectDexDebugMetadataInputSchema,
} from "../../domain/dex/dexDebugMetadataReport.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "inspect_dex_debug_metadata";

/** Shared artifact validation and typed inline Evidence for CLI/MCP. */
export class DexDebugMetadataService {
  constructor(readonly provider: DexDebugMetadataPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  /** Preserve exact selected artifact identity and the decoded debug facts. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const input = inspectDexDebugMetadataInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    const execution = inspected.value;
    const report = dexDebugMetadataResultSchema.safeParse(execution.result);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      !dexDebugMetadataMatchesSubject(
        report.data.artifact,
        execution.subject,
      ) ||
      !dexReportMatchesSelection(report.data, input.data)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "DEX reader returned malformed data, changed the selected artifact identity, or answered a different selection.",
        ),
      );
    // Validated before classifying completion: a late abort keeps the report.
    return completeProviderEvidence(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: {
          path: input.data.path,
          ...(input.data.entry === undefined
            ? {}
            : { entry: input.data.entry }),
          ...(input.data.class_descriptor === undefined
            ? {}
            : { class_descriptor: input.data.class_descriptor }),
        },
        result: report.data,
        ...(execution.rawResult === null
          ? {}
          : { rawResult: execution.rawResult }),
        confidence: "observed",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
      options?.signal,
    );
  }
}
