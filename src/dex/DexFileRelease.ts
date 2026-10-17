/** Identity of REA's in-process DEX reader (no external engine, no device). */
export const DEX_PROVIDER_IDENTITY = {
  id: "dex-file",
  name: "REA DEX reader",
  version: null,
} as const;

export const DEX_LIMITS = {
  /** A single `.dex` far exceeding this is rejected before allocation (real dex ~tens of MiB). */
  inputBytes: 64 * 1024 * 1024,
  /** Ceiling on a selected APK/ZIP's size (its digest is streamed, not retained). */
  archiveBytes: 512 * 1024 * 1024,
  /** Ceiling on an archive's central-directory metadata read. */
  archiveMetadataBytes: 16 * 1024 * 1024,
  /** Inline result ceiling; a decoded result past this is refused, not truncated. */
  outputBytes: 8 * 1024 * 1024,
  /** Cap on auto-loaded multidex members summarized for an archive; refuse past it. */
  maxDexMembers: 64,
  /**
   * Canonical member names remembered for the "not auto-loaded" note, beyond
   * the retained members; further names are counted, not listed.
   */
  maxNamedCanonicalMembers: 128,
  /**
   * UTF-8 bytes of member names one note or refusal spells out; the rest are
   * counted. A stored name can be ~64 KiB, so a count cap alone lets 128 names
   * reach megabytes.
   */
  namedMembersBytes: 4 * 1024,
  /** UTF-16 code units of one member name quoted in prose; longer is shortened, marked. */
  nameDisplayChars: 160,
  /** UTF-16 code units of one archive-reader note carried into `limitations`. */
  noteDisplayChars: 1024,
  /** UTF-8 bytes of archive-reader notes carried into `limitations`; further notes are counted. */
  readerNotesBytes: 8 * 1024,
  /**
   * Work units (debug opcodes, parameter-name reads, class_data entries walked)
   * allowed per member, per byte of that member. Each opcode, encoded_field and
   * encoded_method is at least one byte, class_data is walked twice, and a debug
   * stream is decoded once per distinct (stream, register layout, proto)
   * combination. Compiler output shares a stream only across identical layouts,
   * so real DEX members measure at most ~0.45 units per byte (R8 release) while
   * work stays bounded by the member's size; a crafted file that re-decodes one
   * long stream under many layouts is refused rather than run unbounded.
   */
  workUnitsPerByte: 2,
  /** Floor for the per-member budget, so a tiny member is not over-constrained. */
  minWorkUnits: 1024 * 1024,
  /**
   * Work units decoded between event-loop yields. Decoding is synchronous; a
   * slice this size takes a few milliseconds, so a 64 MiB member no longer
   * blocks other requests (or cancellation) for its whole decode.
   */
  workUnitsPerSlice: 1 << 18,
} as const;
