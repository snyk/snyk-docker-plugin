import { DotnetGraphParseResult, DotnetPackageWithDependencies } from "./types";

interface AssetsTargetEntry {
  dependencies?: Record<string, string>;
}

interface AssetsLibraryEntry {
  type?: string;
}

interface ProjectAssetsJson {
  project?: {
    restore?: {
      projectName?: string;
    };
    frameworks?: Record<
      string,
      {
        dependencies?: Record<string, string>;
      }
    >;
  };
  targets?: Record<string, Record<string, AssetsTargetEntry>>;
  libraries?: Record<string, AssetsLibraryEntry>;
}

function parsePackageKey(
  key: string,
): { name: string; version: string } | null {
  const slashIndex = key.indexOf("/");
  if (slashIndex === -1) {
    return null;
  }
  return {
    name: key.substring(0, slashIndex),
    version: key.substring(slashIndex + 1),
  };
}

export function parseProjectAssetsJson(
  content: string,
): DotnetGraphParseResult | null {
  if (!content || typeof content !== "string") {
    return null;
  }

  let parsed: ProjectAssetsJson;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const targets = parsed.targets;
  const libraries = parsed.libraries;
  if (!targets || !libraries) {
    return null;
  }

  const tfmKeys = Object.keys(targets);
  if (tfmKeys.length === 0) {
    return null;
  }

  const target = targets[tfmKeys[0]];
  if (!target || typeof target !== "object") {
    return null;
  }

  const rootName = parsed.project?.restore?.projectName ?? "project";
  const rootVersion = "0.0.0";

  const frameworkKeys = Object.keys(parsed.project?.frameworks ?? {});
  const frameworkDeps =
    frameworkKeys.length > 0
      ? parsed.project!.frameworks![frameworkKeys[0]].dependencies
      : undefined;

  const directDependencies = frameworkDeps ? Object.keys(frameworkDeps) : [];

  const packageMap = new Map<string, DotnetPackageWithDependencies>();

  for (const key of Object.keys(target)) {
    const library = libraries[key];
    if (library?.type === "project") {
      continue;
    }

    const parsedKey = parsePackageKey(key);
    if (!parsedKey) {
      continue;
    }

    const entry = target[key];
    const dependencies = entry?.dependencies
      ? Object.keys(entry.dependencies)
      : [];

    packageMap.set(parsedKey.name.toLowerCase(), {
      name: parsedKey.name,
      version: parsedKey.version,
      dependencies,
    });
  }

  if (packageMap.size === 0 && directDependencies.length === 0) {
    return null;
  }

  return {
    rootName,
    rootVersion,
    directDependencies,
    packages: Array.from(packageMap.values()),
  };
}
