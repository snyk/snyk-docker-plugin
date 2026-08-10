import { ComposerPackage, ParseComposerLockOptions } from "./types";

interface PackageEntry {
  name?: string;
  version?: string;
}

interface ComposerLockJson {
  packages?: PackageEntry[];
  "packages-dev"?: PackageEntry[];
}

interface InstalledJsonV2 {
  packages?: PackageEntry[];
}

function extractPackages(
  entries: PackageEntry[] | undefined,
): ComposerPackage[] {
  if (!entries || !Array.isArray(entries)) {
    return [];
  }

  const packages: ComposerPackage[] = [];
  for (const entry of entries) {
    if (typeof entry.name === "string" && typeof entry.version === "string") {
      packages.push({ name: entry.name, version: entry.version });
    }
  }
  return packages;
}

export function parseComposerLock(
  content: string,
  options: ParseComposerLockOptions = {},
): ComposerPackage[] {
  const shouldIncludeDevDependencies =
    options.shouldIncludeDevDependencies ?? false;

  let parsed: ComposerLockJson;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return [];
  }

  const packages = extractPackages(parsed.packages);

  if (shouldIncludeDevDependencies) {
    packages.push(...extractPackages(parsed["packages-dev"]));
  }

  return packages;
}

export function parseInstalledJson(content: string): ComposerPackage[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  if (Array.isArray(parsed)) {
    return extractPackages(parsed as PackageEntry[]);
  }

  if (parsed && typeof parsed === "object") {
    return extractPackages((parsed as InstalledJsonV2).packages);
  }

  return [];
}
