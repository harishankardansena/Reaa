/**
 * The logical name the ZIP reader gives an archive member: its stored name
 * without leading `./` segments, so an archive's literal `./Foo.class` is
 * selectable as `Foo.class`. Nothing else is rewritten: a backslash or a
 * leading `/` is part of the stored name and of the member's identity. The
 * reader and every caller-supplied selector use this one transform.
 */
export const normalizeArchiveMemberPath = (entry: string): string =>
  entry.replace(/^(?:\.\/)+/u, "");
