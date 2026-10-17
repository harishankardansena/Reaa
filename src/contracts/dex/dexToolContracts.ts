import {
  dexDebugMetadataResultSchema,
  inspectDexDebugMetadataInputSchema,
} from "../../domain/dex/dexDebugMetadataReport.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static Android DEX debug-readiness inspection of a selected local .dex or APK member. */
export const INSPECT_DEX_DEBUG_METADATA_CONTRACT = {
  name: "inspect_dex_debug_metadata",
  ...toolContractMetadata("inspect_dex_debug_metadata"),
  kind: "artifact-provider",
  description:
    "Judge whether debugging survives in a selected local Android DEX, or the DEX members of an APK/ZIP, before attaching a debugger or reading a decompilation: a per-member readiness summary by default, or per-method detail for one class_descriptor. Reads compiler-emitted debug_info only: no Android code executes, no device or adb is involved, and odex/vdex/oat/cdex are refused. Line numbers may be R8-renumbered; SHA-256 identifies the selected bytes, not authenticity.",
  inputSchema: inspectDexDebugMetadataInputSchema,
  outputSchema: evidenceResultOf(dexDebugMetadataResultSchema),
  examples: [
    {
      title: "Summarize debug readiness across an APK's DEX members",
      input: { path: "/artifacts/app.apk" },
    },
    {
      title:
        "Inspect one class inside a selected DEX for full per-method detail",
      input: {
        path: "/artifacts/classes.dex",
        class_descriptor: "Lcom/example/Service;",
      },
    },
  ],
} as const satisfies ToolContract;

/** Keep the public catalog in its existing order, using its named contract. */
export const DEX_TOOL_CONTRACTS = [
  INSPECT_DEX_DEBUG_METADATA_CONTRACT,
] as const;
