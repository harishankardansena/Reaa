import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, vi } from "vitest";

import type { BrowserScenarioCapturePort } from "../../../src/application/BrowserScenarioCapturePort.js";
import { createBrowserObservationProvider } from "../../../src/composition/browserObservation.js";
import { createElectronObservationProvider } from "../../../src/composition/electronObservation.js";
import { AnalysisInputError } from "../../../src/domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { err } from "../../../src/domain/result.js";
import { silentLogger } from "../../../src/logger.js";
import { startMcpTransport } from "../../../src/main/transport.js";
import type { RuntimeDependencies } from "../../../src/main/types.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

it("keeps the shared browser scenario provider open when the SDK discards its discovery probe", async () => {
  const session = createTestBinarySession(() => {
    throw new Error("Unexpected deep provider");
  });
  const close = vi.fn(async () => undefined);
  const captureScenario = vi.fn(async () =>
    err(
      new AnalysisInputError("capture_browser_scenario", {
        cause: new Error(
          "Controlled provider received the replacement request",
        ),
      }),
    ),
  );
  const browserScenarioCapture: BrowserScenarioCapturePort = {
    identity: () => ({
      id: "fake-browser",
      name: "Fake browser",
      version: "1",
    }),
    captureScenario,
    close,
  };
  const browserObservation = createBrowserObservationProvider();
  const closeBrowser = vi
    .spyOn(browserObservation, "close")
    .mockResolvedValue(undefined);
  const electronObservation = createElectronObservationProvider();
  const cleanupFailure = new ProviderCleanupError(
    "controlled-electron",
    ["controlled-transport"],
    { reason: "Controlled Electron cleanup failure" },
  );
  let cleanupAllowed = false;
  const closeElectron = vi
    .spyOn(electronObservation, "close")
    .mockImplementation(async () => {
      if (!cleanupAllowed) throw cleanupFailure;
    });
  const factories: Parameters<RuntimeDependencies["serve"]>[0][] = [];
  const runtime: RuntimeDependencies = {
    env: {},
    serve: (factory) => {
      factories.push(factory);
      return { close: async () => undefined };
    },
    writeStderr: () => undefined,
    setExitCode: () => undefined,
    registerShutdown: () => () => undefined,
  };
  const transport = await startMcpTransport(runtime, session, {
    logger: silentLogger,
    serverLogger: silentLogger,
    environment: runtime.env,
    delivery: new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE),
    loadOptionalProviders: async () => ({
      browserObservation,
      browserScenarioCapture,
      electronObservation,
    }),
  });
  if (!transport.ok) throw new Error("Transport failed");
  const factory = factories[0];
  if (factory === undefined) throw new Error("Missing SDK server factory");
  try {
    const probe = await factory({ era: "modern" });
    await probe.close();
    const replacement = await factory({ era: "legacy" });
    const client = new Client({ name: "replacement-probe", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await replacement.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "capture_browser_scenario",
        arguments: {
          browser: { mode: "launch", executable_path: process.execPath },
          start_url: { url: "https://app.example.test/", query: [] },
          actions: [
            { step_id: "settle", action: "wait_for_timeout", duration_ms: 1 },
          ],
        },
      });
      expect(captureScenario).toHaveBeenCalledTimes(1);
      expect(parseMcpToolError(result).error).toMatchObject({
        code: "invalid_request",
      });
    } finally {
      await client.close();
    }
    await replacement.close();
    expect(close).not.toHaveBeenCalled();
    expect(closeBrowser).not.toHaveBeenCalled();
    expect(closeElectron).not.toHaveBeenCalled();

    const attempts = await Promise.allSettled([
      transport.closeOptionalProviders(),
      transport.closeOptionalProviders(),
    ]);
    expect(attempts.map(({ status }) => status)).toEqual([
      "rejected",
      "rejected",
    ]);
    for (const attempt of attempts) {
      if (attempt.status === "rejected") {
        expect(attempt.reason).toBeInstanceOf(AggregateError);
        if (!(attempt.reason instanceof AggregateError))
          throw new Error("Expected optional provider cleanup aggregate");
        expect(attempt.reason.errors).toHaveLength(1);
        expect(attempt.reason.errors[0]).toBe(cleanupFailure);
      }
    }
    expect(close).toHaveBeenCalledTimes(1);
    expect(closeBrowser).toHaveBeenCalledTimes(1);
    expect(closeElectron).toHaveBeenCalledTimes(1);
    cleanupAllowed = true;
    await transport.closeOptionalProviders();
    await transport.closeOptionalProviders();
    expect(close).toHaveBeenCalledTimes(1);
    expect(closeBrowser).toHaveBeenCalledTimes(1);
    expect(closeElectron).toHaveBeenCalledTimes(2);
  } finally {
    cleanupAllowed = true;
    await transport.closeOptionalProviders();
    await transport.closeAndroid();
    await session.close();
  }
});

it("closes optional providers when MCP server startup throws", async () => {
  const session = createTestBinarySession(() => {
    throw new Error("Unexpected deep provider");
  });
  const scenarioClose = vi.fn(async () => undefined);
  const browserObservation = createBrowserObservationProvider();
  const browserClose = vi
    .spyOn(browserObservation, "close")
    .mockResolvedValue(undefined);
  const electronObservation = createElectronObservationProvider();
  const electronClose = vi
    .spyOn(electronObservation, "close")
    .mockResolvedValue(undefined);
  const browserScenarioCapture: BrowserScenarioCapturePort = {
    identity: () => ({
      id: "fake-browser",
      name: "Fake browser",
      version: "1",
    }),
    captureScenario: async () => {
      throw new Error("Unexpected scenario capture");
    },
    close: scenarioClose,
  };
  const runtime: RuntimeDependencies = {
    env: {},
    serve: () => {
      throw new Error("Server startup failed");
    },
    writeStderr: () => undefined,
    setExitCode: () => undefined,
    registerShutdown: () => () => undefined,
  };
  try {
    const transport = await startMcpTransport(runtime, session, {
      logger: silentLogger,
      serverLogger: silentLogger,
      environment: runtime.env,
      delivery: new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE),
      loadOptionalProviders: async () => ({
        browserObservation,
        browserScenarioCapture,
        electronObservation,
      }),
    });

    expect(transport).toEqual({ ok: false });
    expect(browserClose).toHaveBeenCalledTimes(1);
    expect(scenarioClose).toHaveBeenCalledTimes(1);
    expect(electronClose).toHaveBeenCalledTimes(1);
  } finally {
    await session.close();
  }
});
