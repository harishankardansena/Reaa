# Verification

Branch `feat/dex-debug-metadata-standalone`, from `main`; independent of #3586.

## Domain, adapter and lifecycle

- 106 unit and adapter tests across the DEX domain (framing, the
  `debug_info_item` state machine, string/proto resolution, summary and detail
  assembly, readiness, cooperative yielding), the provider (loose/APK multidex,
  entry selection, members Android does not auto-load, refusals), failure
  mapping (per-source size limits, cancellation reasons), the service, shared
  modified UTF-8, the magic peek and the ZIP reader's retention, stored-name and
  limit-bound facts.
- 11 process-global lifecycle tests (`tests/process-global/dexProviderLifecycle.test.ts`)
  for a loose `.dex`, an APK summary and an APK `entry` selection: failed
  descriptor close (report or primary failure kept, owner named, cleared by
  `close()` after a failed retry), cancellation during the final close
  (typed, carrying the abort reason), cancellation plus failed close, and a
  failed ZIP reader close (named by owner, report kept, admission blocked until
  `close()` releases it).
- 3 acceptance tests (`tests/acceptance/dexDebugMetadataCli.test.ts`) drive the
  compiled CLI and stdio MCP with in-test DEX/APK fixtures: summary, entry,
  class detail, ambiguity and malformed-input refusals, CLI/MCP result parity,
  and a cancelled MCP call after which the server keeps serving. DEX is in the
  NUL-path rejection table.

## Real-toolchain lane

`npm run verify:dex` (Android SDK d8 + dexdump, JDK javac) compiles an owned
fixture with `-g` and `-g:none`, dexes each, and cross-checks REA against
`dexdump`: the `-g` dex reads `present` with locals (dexdump confirms), a
release dex keeps lines but no local names and reads `partial`, the `-g:none`
dex reads `stripped` with zero locals (dexdump confirms), per-class detail
resolves `compute`/`(IJ)I` and its locals, and the local **names** (`this`,
`a`, `b`) REA reports are names dexdump also resolves. An APK built from the
dex exercises summarize-all, entry selection and a missing-entry input error.
All through the built CLI and the stdio MCP in Evidence parity, advertised
schema validated. 14 cases; skips cleanly without the SDK.

Real APKs through the shared service:

- A debug test APK: 11 members, 260,344 line positions, 192,586 locals, 77,300
  declared locals, 0 unreadable; 8 `present`, 1 `partial`, 2 `stripped`
  (members holding only stripped library code).
- A third-party R8 release APK: 4 members, 5,226,600 line positions, 424,913
  locals (implicit `this`/parameters), 0 declared locals, 0 unreadable; all 4
  `partial` (lines kept, local names gone) — the debug-vs-release signal.

## Independent review — resolved

An independent review found a blocking correctness bug and several
follow-ups, all fixed:

- BLOCKER — the decoder never seeded a method's implicit parameter locals (and
  `this`), so it dropped every parameter + `this` from the local tables and
  flagged valid `DBG_END_LOCAL`/`RESTART` on a parameter register as malformed,
  stopping the walk early and losing line positions. Fixed by seeding the
  implicit locals from the code_item register layout + proto before the walk;
  on a real debug APK `line_positions` now equals dexdump's count.
- `line == 0` tolerated (d8 synthetic methods); only a negative line is malformed.
- Per-class `class_data` method count bounded structurally before allocation.
- The summary memo keys on the full parameter layout (stream, register frame,
  receiver and proto), so seeding cannot leak between methods.
- The real lane cross-checks local tuples (`this` + parameter names) against
  dexdump — the check that would have caught the blocker.

## Pending (follow-ups, not blocking)

- `distinct_source_files` can include d8's synthetic source name
  (`D8$$SyntheticClass`); the `-renamesourcefileattribute` heuristic still holds.
  Documented in the guide.
- A duplicate-class-across-members and a malformed/truncated-DEX case in the
  real-toolchain lane; today they are covered by unit, provider and acceptance
  tests.

## Limits

No Android code executes; no device/adb; `odex`/`vdex`/`oat`/`cdex` refused.
Line positions may be R8-renumbered synthetic lines needing `mapping.txt`.
Real-toolchain validation covers Linux + JDK + Android build-tools 36 only.
Lifecycle faults are injected at the real file handle and the ZIP reader's
close; a real kernel close failure was not reproduced.
