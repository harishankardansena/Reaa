import { z } from "incur";
import type { Logger } from "pino";

import { dexDebugMetadataModule } from "../composition/dex.js";
import { logCliCommand } from "../cliLogging.js";
import { DEX_PROVIDER_IDENTITY } from "../dex/DexFileRelease.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected DEX artifact through the shared workflow. */
export const registerDexCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const service = dexDebugMetadataModule.create(environment);
  cli.command(dexDebugMetadataModule.cliCommand, {
    description:
      "Inspect compiler-emitted debug metadata in a selected local Android .dex, or the DEX members of an APK/ZIP",
    args: z.object({
      path: z
        .string()
        .describe(
          "Local .dex artifact, or an .apk/.zip (its auto-loaded classes*.dex members, or one member with --entry)",
        ),
    }),
    options: z.object({
      entry: z
        .string()
        .optional()
        .describe(
          "DEX member to select inside the archive, e.g. classes2.dex; omit to summarize the members Android auto-loads (classes.dex, classes2.dex, ... up to the first missing name). Members after a gap are not included; select them here",
        ),
      "class-descriptor": z
        .string()
        .optional()
        .describe(
          "Drill into one class for per-method detail, e.g. Lcom/example/Foo;",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, dexDebugMetadataModule.cliCommand, () =>
          finishAnalysisCommand(
            () =>
              service.inspect(
                {
                  path: absoluteCallerPath(args.path),
                  ...(options.entry === undefined
                    ? {}
                    : { entry: options.entry }),
                  ...(options["class-descriptor"] === undefined
                    ? {}
                    : { class_descriptor: options["class-descriptor"] }),
                },
                { signal },
              ),
            service,
            DEX_PROVIDER_IDENTITY.id,
            dexDebugMetadataModule.contract.name,
            undefined,
            signal,
          ),
        ),
      ),
  });
};
