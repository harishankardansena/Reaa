# Implementation plan

Land as its own slice, branched from `main` and independent of the JVM debug
metadata work (#3586). The few helpers both readers need are shared modules
introduced here, so either PR can merge first.

1. **Shared helpers.** The modified-UTF8 decoder (DEX `string_data_item` uses
   the same encoding as JVM class files) in `src/domain/modifiedUtf8.ts`; the
   zip-magic sniff, member-path normalization and bounded member reader in
   `src/artifacts/archiveMember.ts`; and `peekArtifactMagic` in
   `src/artifacts/readStableArtifact.ts`. Whichever of the JVM and DEX PRs merges
   second adopts these instead of its own copies.
2. **Domain.** `dexFile.ts` (bounded framing + LEB128), `dexDebugInfo.ts` (the
   `debug_info_item` state machine with implicit-parameter seeding),
   `dexStrings.ts` (string/type/method/proto resolution),
   `dexDebugMetadata.ts` (summary tally + readiness + per-class detail),
   `dexDebugMetadataReport.ts` (schema + input + projections).
3. **Adapter.** `DexFileProvider.ts` (loose `.dex` + APK multidex, admit-once),
   `dexEntry.ts`, `dexFailures.ts`, `DexFileRelease.ts`.
4. **Application.** `DexDebugMetadataPort.ts` + `DexDebugMetadataService.ts`.
5. **Wiring.** Contract, composition, CLI (`inspect-dex-debug-metadata`), MCP
   registration, effect audit, `TOOL_CONTRACTS`, `createServer`, product catalog.
6. **Tests.** Domain + adapter units (hand-built DEX fixtures, no committed
   binaries); `verify:dex` real lane (d8/dexdump); conformance.
7. **Review.** Independent review; fix findings.
8. **Docs.** This spec dir + the analyst guide + the docs index link.
