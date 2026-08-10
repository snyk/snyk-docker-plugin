import { DotnetGraphParseResult, DotnetPackageWithDependencies } from "./types";

interface LockDependencyEntry {
  type?: string;
  resolved?: string;
  dependencies?: Record<string, string>;
}

interface PackagesLockJson {
  dependencies?: Record<string, Record<string, LockDependencyEntry>>;
}

export function parsePackagesLockJson(
  content: string,
): DotnetGraphParseResult | null {
  if (!content || typeof content !== "string") {
    return null;
  }

  let parsed: PackagesLockJson;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const tfmEntries = parsed.dependencies;
  if (!tfmEntries || typeof tfmEntries !== "object") {
    return null;
  }

  const tfmKeys = Object.keys(tfmEntries);
  if (tfmKeys.length === 0) {
    return null;
  }

  const target = tfmEntries[tfmKeys[0]];
  if (!target || typeof target !== "object") {
    return null;
  }

  let rootName = "project";
  const rootVersion = "0.0.0";
  const packageMap = new Map<string, DotnetPackageWithDependencies>();
  const directDependencyNames = new Set<string>();

  for (const [pkgName, entry] of Object.entries(target)) {
    if (!entry || typeof entry !== "object") {
      continue;
    }

    const entryType = entry.type ?? "";

    if (entryType === "Project") {
      rootName = pkgName;
      if (entry.dependencies) {
        for (const depName of Object.keys(entry.dependencies)) {
          directDependencyNames.add(depName);
        }
      }
      continue;
    }

    if (entryType === "Direct") {
      directDependencyNames.add(pkgName);
    }

    const resolved = entry.resolved;
    if (!resolved || typeof resolved !== "string") {
      continue;
    }

    const dependencies = entry.dependencies
      ? Object.keys(entry.dependencies)
      : [];

    packageMap.set(pkgName.toLowerCase(), {
      name: pkgName,
      version: resolved,
      dependencies,
    });
  }

  if (packageMap.size === 0 && directDependencyNames.size === 0) {
    return null;
  }

  return {
    rootName,
    rootVersion,
    directDependencies: Array.from(directDependencyNames),
    packages: Array.from(packageMap.values()),
  };
}
