/**
 * Display text for the member names and archive-reader notes the DEX reader
 * writes into `limitations` and refusals. Only prose is shortened, always with
 * an explicit marker; identity values (a member's reported `entry`) are never
 * altered. A stored ZIP name can be ~64 KiB, so without these bounds one
 * crafted archive turns a note into megabytes.
 */
import { DEX_LIMITS } from "./DexFileRelease.js";

const utf8Bytes = (text: string): number => Buffer.byteLength(text, "utf8");

const isHighSurrogate = (code: number): boolean =>
  code >= 0xd800 && code <= 0xdbff;

/**
 * The start and end of `text` worth `max` UTF-16 code units in all, never
 * splitting a surrogate pair. Both ends are kept because a crafted name hides
 * what distinguishes it (e.g. `classes7.dex`) behind a long prefix.
 */
const ends = (
  text: string,
  max: number,
): { readonly start: string; readonly end: string } => {
  let startLength = Math.ceil(max / 2);
  if (isHighSurrogate(text.charCodeAt(startLength - 1))) startLength -= 1;
  let endFrom = text.length - (max - Math.ceil(max / 2));
  if (isHighSurrogate(text.charCodeAt(endFrom - 1))) endFrom += 1;
  return { start: text.slice(0, startLength), end: text.slice(endFrom) };
};

const shortened = (
  text: string,
  max: number,
  kind: "name" | "note",
  quote: (part: string) => string,
): string => {
  if (text.length <= max) return quote(text);
  const { start, end } = ends(text, max);
  return `${quote(start)}…${quote(end)} (${kind} shortened: ${String(start.length + end.length)} of ${String(text.length)} characters shown)`;
};

/**
 * A member name as prose shows it, JSON-quoted when `quoted`; past the display
 * bound its start and end are shown, each quoted, with a marker.
 */
export const displayName = (name: string, quoted = false): string =>
  shortened(name, DEX_LIMITS.nameDisplayChars, "name", (part) =>
    quoted ? JSON.stringify(part) : part,
  );

/** An archive-reader note as carried into `limitations`, shortened past the display bound. */
export const displayNote = (note: string): string =>
  shortened(note, DEX_LIMITS.noteDisplayChars, "note", (part) => part);

/**
 * Distinct names remembered for display, bounded by count and by the UTF-8
 * bytes of their display text; every name not kept is counted, so a note can
 * say how many members it did not name. A name already kept costs nothing.
 */
export class NamedMembers {
  readonly #names = new Set<string>();
  readonly #quoted: boolean;
  #bytes = 0;
  #unnamed = 0;

  constructor(quoted: boolean) {
    this.#quoted = quoted;
  }

  add(name: string): void {
    if (this.#names.has(name)) return;
    // Each name costs its display text plus the ", " separator.
    const cost = utf8Bytes(displayName(name, this.#quoted)) + 2;
    if (
      this.#names.size < DEX_LIMITS.maxNamedCanonicalMembers &&
      this.#bytes + cost <= DEX_LIMITS.namedMembersBytes
    ) {
      this.#names.add(name);
      this.#bytes += cost;
    } else this.#unnamed += 1;
  }

  get names(): ReadonlySet<string> {
    return this.#names;
  }

  /** Members whose name was not kept (each occurrence counts once). */
  get unnamed(): number {
    return this.#unnamed;
  }

  display(name: string): string {
    return displayName(name, this.#quoted);
  }
}
