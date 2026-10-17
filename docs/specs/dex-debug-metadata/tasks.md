# Tasks

- [x] Confirm scope: static `.dex`/APK inspection, in-scope, no device/adb/JDWP.
- [x] Add shared modified-UTF8, archive-member and magic-peek helpers.
- [x] Dependency-free DEX framing (bounded, `Result`-based; version/endian/cdex gating).
- [x] Decode the `debug_info_item` state machine, seeding implicit parameter + `this` locals.
- [x] Resolve names/types/descriptors from the string/type/proto pools (bounded).
- [x] Assemble the summary (tallies + readiness) and per-class detail.
- [x] Public schema + input (`path`, `entry?`, `class_descriptor?`) + projections.
- [x] Provider (loose `.dex` + APK multidex, admit-once, ambiguity/encrypted refusals), service.
- [x] CLI/MCP contract, catalog registration, effect audit, composition/server wiring.
- [x] Unit + adapter tests; `verify:dex` d8/dexdump real lane (cross-checks local tuples).
- [x] Resolve independent review findings (implicit-parameter seeding blocker et al.).
- [x] Resolve PR review findings: archive descriptor/reader lifecycle, real
      in-pass cancellation, per-source size limits, one readiness vocabulary,
      mode-keyed schema, public CLI/MCP acceptance test.
- [x] Analyst guide + spec dir + docs index link.
- [x] Discoverability parity (README capability row, reverse-engineer skill source,
      architecture.mermaid) — landed for both the JVM and DEX tools.
- [x] Focused gates at PR time (`check:fast`, `docs:check`, `mcp-catalog:check`,
      `format:check`, `verify:module-boundaries`, `verify:dex`, focused lifecycle
      boundary tests). The complete `check:pr` gate is optional and was not run.
