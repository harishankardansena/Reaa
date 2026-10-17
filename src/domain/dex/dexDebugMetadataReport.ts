/**
 * Public contract shape for `inspect_dex_debug_metadata` and the projection from
 * decoded DEX facts into that JSON. The domain owns the schema so CLI and MCP
 * present identical, validated facts. Two modes: a whole-file (per-dex-member)
 * readiness `summary`, and full per-method `class-detail` for one selected class.
 */
import { z } from "zod";

import { normalizeArchiveMemberPath } from "../archiveMemberPath.js";

import type { EvidenceSubjectTarget } from "../evidence.js";
import { localPathStringSchema } from "../localPath.js";
import type { DexClassDetail, DexSummary } from "./dexDebugMetadata.js";

const digest = z.string().regex(/^[a-f0-9]{64}$/);

/** A DEX type descriptor in internal form, e.g. `Lcom/example/Foo;`. */
const CLASS_DESCRIPTOR = /^L[^;]+;$/;

/** All artifacts are explicitly selected local files; references never trigger acquisition. */
export const inspectDexDebugMetadataInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute selected local .dex artifact, or an APK/ZIP (its auto-loaded classes*.dex members, or one member when entry is given)",
  ),
  entry: z
    .string()
    .min(1)
    .optional()
    .describe(
      "DEX member to select inside an APK/ZIP at path, e.g. classes2.dex; omit to summarize the members Android auto-loads (classes.dex, classes2.dex, ... up to the first missing name). Members after a gap are not included; select them here",
    ),
  class_descriptor: z
    .string()
    .regex(
      CLASS_DESCRIPTOR,
      "Expected a type descriptor in Lpackage/Name; form",
    )
    .optional()
    .describe(
      "Drill into one class for full per-method detail, e.g. Lcom/example/Foo;; omit for the readiness summary",
    ),
});
export type InspectDexDebugMetadataInput = z.infer<
  typeof inspectDexDebugMetadataInputSchema
>;

/**
 * Same vocabulary as a method's state: line positions and local evidence both
 * observed is `present`, exactly one is `partial`, neither is `stripped`.
 * `unknown`: the observed evidence does not settle the label and damaged
 * structures (see `unreadable`) could have hidden the rest.
 */
const readiness = z.enum(["present", "partial", "stripped", "unknown"]);

const summarySchema = z.strictObject({
  dex_version: z.string(),
  class_count: z.number().int().nonnegative(),
  methods_with_code: z.number().int().nonnegative(),
  methods_with_debug_info: z.number().int().nonnegative(),
  methods_with_parameter_names: z.number().int().nonnegative(),
  line_positions: z.number().int().nonnegative(),
  /** Every local dexdump lists, including implicit `this`/parameter locals. */
  local_declarations: z.number().int().nonnegative(),
  /** Locals the debug streams declare themselves; drives `readiness`. */
  explicit_local_declarations: z.number().int().nonnegative(),
  set_file_events: z.number().int().nonnegative(),
  source_file_present: z.number().int().nonnegative(),
  distinct_source_files: z.strictObject({
    /** Distinct `source_file_idx` string_ids (not decoded texts). */
    count: z.number().int().nonnegative(),
    sample: z.array(z.string()),
  }),
  /**
   * Structures that could not be read; their debug metadata is unknown, not
   * absent. Non-zero values make `readiness` unknown unless both line and
   * local evidence were found.
   */
  unreadable: z.strictObject({
    class_data: z.number().int().nonnegative(),
    code_items: z.number().int().nonnegative(),
    debug_info: z.number().int().nonnegative(),
  }),
  readiness,
});

const memberSummarySchema = z.strictObject({
  entry: z.string().nullable(),
  sha256: digest,
  bytes: z.number().int().nonnegative(),
  summary: summarySchema,
});

const localSchema = z.strictObject({
  register: z.number().int().nonnegative(),
  name: z.string().nullable(),
  type: z.string().nullable(),
  signature: z.string().nullable(),
  start_address: z.number().int(),
  end_address: z.number().int(),
  out_of_range: z.boolean(),
});

const methodDetailSchema = z.strictObject({
  name: z.string().nullable(),
  descriptor: z.string().nullable(),
  state: z.enum([
    "present",
    "partial",
    "stripped",
    "malformed",
    "not-applicable",
  ]),
  has_code: z.boolean(),
  line_count: z.number().int().nonnegative(),
  parameter_names: z.array(z.string().nullable()),
  locals: z.array(localSchema),
  set_file_events: z.number().int().nonnegative(),
});

const classDetailSchema = z.strictObject({
  entry: z.string().nullable(),
  /** The selected class was matched by this exact descriptor. */
  descriptor: z.string(),
  source_file: z.string().nullable(),
  methods: z.array(methodDetailSchema),
});

const reportFields = {
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: z.number().int().nonnegative(),
  }),
  container: z.enum(["dex-file", "apk", "zip"]),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
};

export const dexDebugMetadataResultSchema = z.discriminatedUnion("mode", [
  z.strictObject({
    ...reportFields,
    mode: z.literal("summary"),
    /** One per summarized DEX member (just one for a loose .dex or a selected entry). */
    members: z.array(memberSummarySchema),
  }),
  z.strictObject({
    ...reportFields,
    mode: z.literal("class-detail"),
    class_detail: classDetailSchema,
  }),
]);
export type DexDebugMetadataResult = z.infer<
  typeof dexDebugMetadataResultSchema
>;

const DEX_DEBUG_METADATA_LIMITATIONS: readonly string[] = [
  "Static DEX inspection only. No Android code executes; positions, registers and names are read from compiler-emitted debug_info, not from a decompiler or a live process.",
  "Line positions are compiler-emitted and may be R8/ProGuard-renumbered synthetic lines that require a mapping.txt to retrace; they are not asserted source lines.",
  'A single distinct source-file name across classes (e.g. "SourceFile") indicates -renamesourcefileattribute; readiness is a conservative derived label over observed tallies.',
  "SHA-256 identifies the exact selected bytes; it does not establish authenticity or which compiler produced the artifact. Only canonical .dex is read; odex/vdex/oat/cdex are refused.",
];

const projectSummary = (
  summary: DexSummary,
): z.infer<typeof summarySchema> => ({
  dex_version: summary.dexVersion,
  class_count: summary.classCount,
  methods_with_code: summary.methodsWithCode,
  methods_with_debug_info: summary.methodsWithDebugInfo,
  methods_with_parameter_names: summary.methodsWithParameterNames,
  line_positions: summary.linePositions,
  local_declarations: summary.localDeclarations,
  explicit_local_declarations: summary.explicitLocalDeclarations,
  set_file_events: summary.setFileEvents,
  source_file_present: summary.sourceFilePresent,
  distinct_source_files: {
    count: summary.distinctSourceFiles.count,
    sample: [...summary.distinctSourceFiles.sample],
  },
  unreadable: {
    class_data: summary.unreadable.classData,
    code_items: summary.unreadable.codeItems,
    debug_info: summary.unreadable.debugInfo,
  },
  readiness: summary.readiness,
});

export interface DexArtifactIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface DexSummaryMember {
  readonly entry: string | null;
  readonly sha256: string;
  readonly bytes: number;
  readonly summary: DexSummary;
}

/** Project a whole-file (per-member) readiness summary. */
export const buildDexSummaryResult = (
  artifact: DexArtifactIdentity,
  container: DexDebugMetadataResult["container"],
  members: readonly DexSummaryMember[],
): DexDebugMetadataResult => ({
  artifact,
  container,
  mode: "summary",
  members: members.map((m) => ({
    entry: m.entry,
    sha256: m.sha256,
    bytes: m.bytes,
    summary: projectSummary(m.summary),
  })),
  runtime_execution: "not-performed",
  limitations: [...DEX_DEBUG_METADATA_LIMITATIONS],
});

/** Project full per-method detail for one selected class. */
export const buildDexClassDetailResult = (
  artifact: DexArtifactIdentity,
  container: DexDebugMetadataResult["container"],
  found: { readonly entry: string | null; readonly detail: DexClassDetail },
  /** The descriptor the class was matched by (resolution may decode it as null). */
  descriptor: string,
): DexDebugMetadataResult => ({
  artifact,
  container,
  mode: "class-detail",
  class_detail: {
    entry: found.entry,
    descriptor,
    source_file: found.detail.sourceFile,
    methods: found.detail.methods.map((m) => ({
      name: m.name,
      descriptor: m.descriptor,
      state: m.state,
      has_code: m.hasCode,
      line_count: m.lineCount,
      parameter_names: [...m.parameterNames],
      locals: m.locals.map((l) => ({
        register: l.register,
        name: l.name,
        type: l.type,
        signature: l.signature,
        start_address: l.startAddress,
        end_address: l.endAddress,
        out_of_range: l.outOfRange,
      })),
      set_file_events: m.setFileEvents,
    })),
  },
  runtime_execution: "not-performed",
  limitations: [...DEX_DEBUG_METADATA_LIMITATIONS],
});

/** The returned artifact identity must match the caller-selected local file. */
export const dexDebugMetadataMatchesSubject = (
  artifact: DexDebugMetadataResult["artifact"],
  subject: EvidenceSubjectTarget,
): boolean =>
  artifact.sha256 === subject.sha256 &&
  artifact.path === subject.path &&
  (subject.format === "file" ||
    subject.format === "apk" ||
    subject.format === "zip");

/** Whether a reported stored member name answers a normalized `entry`. */
const answersEntry = (
  reported: string | null | undefined,
  requested: string,
): boolean =>
  typeof reported === "string" &&
  normalizeArchiveMemberPath(reported) === requested;

/**
 * The report answers exactly what was asked: class detail iff a class was
 * requested (for that class), and, when an entry was selected, only that
 * member. Guards the application boundary against a provider answering a
 * different selection under the caller's parameters. A member is reported
 * under its raw stored name while `entry` may omit a leading `./`, so both
 * sides are compared in the one shared normalized form; the reader refuses a
 * request that more than one stored spelling could answer.
 */
export const dexReportMatchesSelection = (
  report: DexDebugMetadataResult,
  selection: {
    readonly entry?: string | undefined;
    readonly class_descriptor?: string | undefined;
  },
): boolean => {
  const entry =
    selection.entry === undefined
      ? undefined
      : normalizeArchiveMemberPath(selection.entry);
  if (report.mode === "summary")
    return (
      selection.class_descriptor === undefined &&
      (entry === undefined ||
        (report.members.length === 1 &&
          answersEntry(report.members[0]?.entry, entry)))
    );
  return (
    report.class_detail.descriptor === selection.class_descriptor &&
    (entry === undefined || answersEntry(report.class_detail.entry, entry))
  );
};
