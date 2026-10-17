/**
 * Choose which DEX members of an APK/ZIP one inspection reads: the member the
 * caller selected with `entry`, or the multidex sequence Android auto-loads.
 * Both match the raw stored central-directory name, as ART's libziparchive
 * does (a leading `./` is optional in `entry`, and the exactly stored
 * spelling wins when the archive holds several); the Info-ZIP Unicode Path
 * name is never consulted. Canonical members Android would not load are named
 * (never silently dropped) on the summary and on every selection refusal,
 * within a byte budget past which they are counted.
 */
import type { ArtifactEntry } from "../artifacts/ArtifactReader.js";
import type { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import { normalizeArchiveMemberPath } from "../domain/archiveMemberPath.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  autoLoadedDexMembers,
  multidexIndex,
  multidexName,
} from "./dexEntry.js";
import { displayName, NamedMembers } from "./dexDisplayText.js";
import { DEX_LIMITS } from "./DexFileRelease.js";

const OPERATION = "inspect_dex_debug_metadata";

interface Candidate {
  /** The member's raw stored name, which ART also uses (never a Unicode Path name). */
  readonly entry: string;
  readonly member: ArtifactEntry;
}

/** The members to analyse and, when any, the note naming members Android skips. */
export interface DexMemberSelection {
  readonly members: readonly Candidate[];
  readonly skippedNote?: string;
}

/** What one enumeration of the archive kept. */
interface ArchiveListing {
  /** Openable members: the requested name, or canonical names within the cap. */
  readonly candidates: readonly Candidate[];
  /**
   * Occurrences, symbolic-link members included, by the requested name or by
   * exact stored canonical name.
   */
  readonly occurrences: ReadonlyMap<string, number>;
  /** Members (symbolic links included) stored exactly as the caller spelled `entry`. */
  readonly exactOccurrences: number;
  /** Whether a member stored exactly as `entry` is a symbolic link. */
  readonly exactSymlink: boolean;
  /** Stored spellings matching the requested name, bounded for display. */
  readonly spellings: NamedMembers;
  /** ZIP directory members (stored with a trailing `/`) matching the requested name. */
  readonly directories: number;
  /** Symbolic-link members matching the requested name. */
  readonly symlinks: number;
  /**
   * Exactly stored canonical names within the member cap held by
   * symbolic-link members; only those inside the auto-loaded run matter.
   */
  readonly symlinkRoots: ReadonlySet<string>;
  /** Canonical names by stored spelling, bounded for display. */
  readonly canonical: NamedMembers;
  /**
   * Length of the contiguous run of exactly stored canonical names from
   * `classes.dex`: the members Android auto-loads, counted over the whole
   * listing (by name only), so it can exceed the retained candidates.
   */
  readonly autoLoaded: number;
}

/**
 * Canonical names an archive can hold: each central-directory record is 46
 * bytes plus a name of at least `classes.dex`, inside the metadata read. A
 * load position at or past this cannot belong to the auto-loaded run.
 */
const MAX_CANONICAL_RECORDS = Math.ceil(
  DEX_LIMITS.archiveMetadataBytes / (46 + "classes.dex".length),
);

const entryError = (message: string): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path: ["entry"], reason: "invalid_value", message },
  ]);

/**
 * Enumerate once, keeping only members this call may open (the reader retains
 * ~8 KB of decoded metadata per kept entry): the requested name, or the
 * canonical names up to one past the member cap (enough to detect "over the
 * cap"). Two occurrences of a name already prove it ambiguous, so no more are
 * kept; the exactly stored spelling of `entry` is kept on its own count, so
 * other spellings of the same name cannot crowd it out. Canonical names past
 * the cap, and the spellings of a requested name, are remembered by name
 * only, bounded.
 *
 * A member stored with a symbolic-link unix mode is never opened (the shared
 * reader does not read link members), but it is counted where ART would see
 * it: ART ignores the mode and loads its bytes, so it holds its place in the
 * auto-loaded run and answers `entry`, and its debug metadata is unavailable,
 * not absent.
 */
const listArchive = async (
  reader: ZipArtifactReader,
  entry: string | undefined,
  requested: string | undefined,
  signal: AbortSignal | undefined,
): Promise<ArchiveListing> => {
  const candidates: Candidate[] = [];
  const occurrences = new Map<string, number>();
  let exactOccurrences = 0;
  let exactSymlink = false;
  const spellings = new NamedMembers(true);
  let directories = 0;
  let symlinks = 0;
  const symlinkRoots = new Set<string>();
  const canonical = new NamedMembers(false);
  // Load positions of exactly stored canonical names, one bit each (~36 KiB).
  const exactPositions = new Uint8Array(Math.ceil(MAX_CANONICAL_RECORDS / 8));
  // ART (libziparchive) finds members by their raw central-directory name and
  // ignores the Info-ZIP Unicode Path field, so the stored name, not the
  // logical path, decides eligibility and is the member's reported identity.
  const wanted = (stored: string): boolean => {
    if (requested !== undefined)
      return normalizeArchiveMemberPath(stored) === requested;
    const index = multidexIndex(normalizeArchiveMemberPath(stored));
    if (index === null) return false;
    canonical.add(stored);
    // Only an exactly stored canonical name is auto-loaded, so a member
    // stored as `./classes.dex` is not (it stays selectable).
    if (multidexIndex(stored) === null) return false;
    if (index < MAX_CANONICAL_RECORDS)
      exactPositions[index >>> 3]! |= 1 << (index & 7);
    return index <= DEX_LIMITS.maxDexMembers;
  };
  const keep = (member: ArtifactEntry): boolean => {
    const stored = member.storedPath ?? member.path;
    if (member.kind === "directory") {
      if (
        requested !== undefined &&
        normalizeArchiveMemberPath(stored) === requested
      )
        directories += 1;
      return false;
    }
    const symlink = member.kind === "symlink";
    if ((member.kind !== "file" && !symlink) || !wanted(stored)) return false;
    // Every occurrence is counted for the report; two are enough to keep.
    const key = requested ?? stored;
    const seen = (occurrences.get(key) ?? 0) + 1;
    occurrences.set(key, seen);
    let exact = false;
    if (requested !== undefined) {
      spellings.add(stored);
      if (stored === entry) {
        exactOccurrences += 1;
        exactSymlink ||= symlink;
        exact = exactOccurrences <= 2;
      }
    }
    if (symlink) {
      if (requested === undefined) symlinkRoots.add(stored);
      else symlinks += 1;
      return false;
    }
    if (seen > 2 && !exact) return false;
    candidates.push({ entry: stored, member });
    return true;
  };
  for await (const member of reader.entries(signal, { retain: keep }))
    void member;
  let autoLoaded = 0;
  while (
    autoLoaded < MAX_CANONICAL_RECORDS &&
    (exactPositions[autoLoaded >>> 3]! & (1 << (autoLoaded & 7))) !== 0
  )
    autoLoaded += 1;
  return {
    candidates,
    occurrences,
    exactOccurrences,
    exactSymlink,
    spellings,
    directories,
    symlinks,
    symlinkRoots,
    canonical,
    autoLoaded,
  };
};

/** Whether a stored spelling is one of the members Android auto-loads. */
const isAutoLoaded = (stored: string, listing: ArchiveListing): boolean => {
  const index = multidexIndex(stored);
  return index !== null && index < listing.autoLoaded;
};

/**
 * Name the canonical members Android does not auto-load, if any: those after
 * a gap in the sequence and those not stored under their exact name.
 */
const skippedMembersNote = (
  path: string,
  listing: ArchiveListing,
): string | undefined => {
  const { canonical } = listing;
  const skipped = [...canonical.names]
    .filter((name) => !isAutoLoaded(name, listing))
    .sort(
      (a, b) =>
        (multidexIndex(normalizeArchiveMemberPath(a)) ?? 0) -
        (multidexIndex(normalizeArchiveMemberPath(b)) ?? 0),
    );
  // Every auto-loaded position has an exactly stored entry; those not named
  // were counted among the unnamed ones.
  const namedLoaded = canonical.names.size - skipped.length;
  const more = Math.max(
    0,
    canonical.unnamed - (listing.autoLoaded - namedLoaded),
  );
  if (skipped.length === 0 && more === 0) return undefined;
  const names = [
    ...skipped.map((name) => canonical.display(name)),
    ...(more === 0 ? [] : [`${String(more)} more canonical DEX member(s)`]),
  ].join(", ");
  return `${path} also holds ${names}, which Android does not auto-load: it loads classes.dex, classes2.dex, ... only while each is present under its exact stored name. Select ${skipped.length + more === 1 ? "it" : "one"} with entry.`;
};

/** The auto-loaded sequence, refused when it cannot be read as promised. */
const resolveAutoLoaded = (
  path: string,
  listing: ArchiveListing,
): Result<DexMemberSelection, AnalysisError> => {
  // Only the contiguous sequence Android loads is promised; a member after a
  // gap is never loaded, so it can neither fail nor shadow the inspection.
  const sequence = autoLoadedDexMembers(
    listing.candidates.map(({ entry }) => entry),
  );
  const loadOrder = new Map(sequence.map((name, index) => [name, index]));
  const matches = listing.candidates.filter(({ entry }) =>
    loadOrder.has(entry),
  );
  // Absence from the summary must not be mistaken for absence from the archive.
  const skippedNote = skippedMembersNote(path, listing);
  const withSkipped = (message: string): string =>
    skippedNote === undefined ? message : `${message} ${skippedNote}`;
  // Every root member is promised, so one that cannot be read is refused,
  // never silently skipped (that would turn unknown into absent).
  const encrypted = matches.filter((m) => m.member.encrypted);
  if (encrypted.length > 0)
    return err(
      new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        withSkipped(
          `${path} has encrypted root DEX member(s) (${encrypted.map((m) => m.entry).join(", ")}); their debug metadata is unavailable, not absent.`,
        ),
        {
          remediationAction:
            "Select a readable member with entry to inspect it alone.",
        },
      ),
    );
  // ART ignores the unix mode and loads a link member's bytes; truncating the
  // run before it would report a shorter sequence than Android loads.
  const linked = [...listing.symlinkRoots]
    .filter((name) => isAutoLoaded(name, listing))
    .sort((a, b) => (multidexIndex(a) ?? 0) - (multidexIndex(b) ?? 0));
  if (linked.length > 0)
    return err(
      new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        withSkipped(
          `${path} has root DEX member(s) stored with a symbolic-link mode (${linked.join(", ")}), which Android loads but REA does not read; their debug metadata is unavailable, not absent.`,
        ),
        {
          remediationAction:
            "Select a readable member with entry to inspect it alone.",
        },
      ),
    );
  // A reported entry must identify exactly one member.
  const ambiguous = sequence.find(
    (name) => (listing.occurrences.get(name) ?? 0) > 1,
  );
  if (ambiguous !== undefined)
    return err(
      entryError(
        withSkipped(
          `${path} holds ${String(listing.occurrences.get(ambiguous))} members named ${ambiguous}; the identity is ambiguous.`,
        ),
      ),
    );
  if (matches.length === 0)
    return err(
      entryError(
        withSkipped(
          `${path} holds no classes.dex under that exact stored name for Android to load; select a .dex with entry.`,
        ),
      ),
    );
  if (matches.length > DEX_LIMITS.maxDexMembers)
    return err(
      new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        withSkipped(
          `${path} auto-loads ${String(listing.autoLoaded)} DEX members (classes.dex … ${multidexName(listing.autoLoaded - 1)}), more than the ${String(DEX_LIMITS.maxDexMembers)}-member limit, so none was read; select one with entry.`,
        ),
        { maximum_dex_members: DEX_LIMITS.maxDexMembers },
        {
          remediationAction:
            "Select one member with entry; members are inspected one at a time.",
        },
      ),
    );
  matches.sort(
    (a, b) => (loadOrder.get(a.entry) ?? 0) - (loadOrder.get(b.entry) ?? 0),
  );
  return ok({
    members: matches,
    ...(skippedNote === undefined ? {} : { skippedNote }),
  });
};

/** The stored spellings that answer a requested name, for a refusal. */
const spellingsOf = ({ spellings }: ArchiveListing): string =>
  [
    ...[...spellings.names].map((name) => spellings.display(name)),
    ...(spellings.unnamed === 0
      ? []
      : [
          `${String(spellings.unnamed)} more member(s) under spellings not named here`,
        ]),
  ].join(", ");

const symlinkRefusal = (path: string, entry: string): AnalysisError =>
  new AnalysisUnsupportedTargetError(
    OPERATION,
    path,
    `The selected entry ${displayName(entry, true)} is stored with a symbolic-link mode, which REA does not read; its debug metadata is unavailable, not absent.`,
  );

/**
 * The one member the caller selected with `entry`: the member stored exactly
 * as spelled when there is one (ART looks members up by exact stored name),
 * otherwise the only member whose stored name normalizes to it.
 */
const resolveRequested = (
  path: string,
  entry: string,
  requested: string,
  listing: ArchiveListing,
): Result<DexMemberSelection, AnalysisError> => {
  if (listing.exactOccurrences > 1)
    return err(
      entryError(
        `${path} holds ${String(listing.exactOccurrences)} members stored as ${displayName(entry, true)}; the identity is ambiguous.`,
      ),
    );
  if (listing.exactSymlink) return err(symlinkRefusal(path, entry));
  const exact = listing.candidates.filter((m) => m.entry === entry);
  const matches = exact.length === 1 ? exact : listing.candidates;
  if (matches.length + (exact.length === 1 ? 0 : listing.symlinks) > 1)
    return err(
      entryError(
        `${path} holds ${String(listing.occurrences.get(requested) ?? 0)} members named ${displayName(requested)} (stored as ${spellingsOf(listing)}); the identity is ambiguous. Select one by its exact stored name.`,
      ),
    );
  const only = matches[0];
  if (only === undefined)
    return listing.symlinks > 0
      ? err(symlinkRefusal(path, entry))
      : listing.directories > 0
        ? err(
            new AnalysisUnsupportedTargetError(
              OPERATION,
              path,
              `The selected entry ${displayName(entry)} is stored as a ZIP directory, which REA does not read as member bytes; its debug metadata is unavailable, not absent.`,
            ),
          )
        : err(
            entryError(
              `No member ${displayName(requested)} exists in ${path}.`,
            ),
          );
  if (only.member.encrypted)
    return err(
      new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `The selected member ${displayName(only.entry)} is encrypted and cannot be read without a key; unavailable, not absent.`,
      ),
    );
  return ok({ members: [only] });
};

/** Choose the archive's DEX members: the explicit entry, or the auto-loaded multidex sequence. */
export const selectDexMembers = async (
  reader: ZipArtifactReader,
  entry: string | undefined,
  path: string,
  signal: AbortSignal | undefined,
): Promise<Result<DexMemberSelection, AnalysisError>> => {
  const requested =
    entry === undefined ? undefined : normalizeArchiveMemberPath(entry);
  const listing = await listArchive(reader, entry, requested, signal);
  return entry === undefined || requested === undefined
    ? resolveAutoLoaded(path, listing)
    : resolveRequested(path, entry, requested, listing);
};
