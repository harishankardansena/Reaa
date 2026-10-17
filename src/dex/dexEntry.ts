/**
 * Multidex member selection inside an APK/ZIP. Android auto-loads the root
 * member `classes.dex`, then `classes2.dex`, `classes3.dex`, … and stops at the
 * first missing name (ART's DexFileLoader). `classes1.dex`, zero-padded names
 * and members after a gap are never auto-loaded; a caller may still select any
 * `.dex` member explicitly by its exact path.
 */

/** A canonical multidex name: `classes.dex` or `classesN.dex` with N >= 2. */
const CANONICAL = /^classes(?:[2-9]|[1-9][0-9]+)?\.dex$/;

/** Load position of a canonical name (`classes.dex` is 0), or null for any other name. */
export const multidexIndex = (path: string): number | null => {
  if (!CANONICAL.test(path)) return null;
  const digits = path.slice("classes".length, -".dex".length);
  return digits === "" ? 0 : Number(digits) - 1;
};

/** ART's name for the `index`-th auto-loaded member (0-based). */
export const multidexName = (index: number): string =>
  index === 0 ? "classes.dex" : `classes${String(index + 1)}.dex`;

/**
 * The members Android auto-loads, in load order: the contiguous canonical
 * sequence starting at `classes.dex` among `paths`.
 */
export const autoLoadedDexMembers = (
  paths: Iterable<string>,
): readonly string[] => {
  const present = new Set(paths);
  const sequence: string[] = [];
  while (present.has(multidexName(sequence.length)))
    sequence.push(multidexName(sequence.length));
  return sequence;
};
