/**
 * Best-effort reader for the root `[package]` table in a Cargo.toml manifest.
 * Only plain-string `name` and `version` fields are supported; workspace
 * inheritance and other TOML forms fall back to version "0.0.0" or undefined.
 * Parsing failures are never fatal — callers treat undefined as "no manifest".
 */
export function parseCargoTomlRootPackage(
  content: string,
): { name: string; version: string } | undefined {
  if (!content || !content.trim()) {
    return undefined;
  }

  try {
    const lines = content.split("\n");
    let inPackageTable = false;
    let name: string | undefined;
    let version: string | undefined;

    for (const rawLine of lines) {
      const line = rawLine.trim();

      if (line.startsWith("#") || line === "") {
        continue;
      }

      if (/^\[.+\]$/.test(line)) {
        const tableName = line.slice(1, -1).trim();
        inPackageTable = tableName === "package";
        continue;
      }

      if (!inPackageTable) {
        continue;
      }

      const nameMatch = line.match(/^name\s*=\s*"(.+)"$/);
      if (nameMatch) {
        name = nameMatch[1];
        continue;
      }

      const versionMatch = line.match(/^version\s*=\s*"(.+)"$/);
      if (versionMatch) {
        version = versionMatch[1];
        continue;
      }

      if (/^version\.workspace\s*=\s*true$/.test(line)) {
        version = "0.0.0";
        continue;
      }

      if (/^version\s*=\s*\{\s*workspace\s*=\s*true\s*\}$/.test(line)) {
        version = "0.0.0";
      }
    }

    if (!name) {
      return undefined;
    }

    return { name, version: version ?? "0.0.0" };
  } catch {
    return undefined;
  }
}
