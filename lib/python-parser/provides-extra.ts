// https://packaging.python.org/en/latest/specifications/core-metadata/#provides-extra-multiple-use
const PROVIDES_EXTRA = "Provides-Extra:";

// given the lines of a METADATA file, find all 'Provides-Extra' names
export function findProvidesExtras(lines: string[]): string[] {
  const extras = new Set<string>();
  for (const line of lines) {
    const l = line.trim();
    if (l.startsWith(PROVIDES_EXTRA)) {
      const extra = l.substring(PROVIDES_EXTRA.length).trim();
      extras.add(extra);
    }
  }
  return Array.from(extras);
}
