import { DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import * as path from "path";
import { getErrorMessage } from "../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const debug = Debug("snyk");

interface DepsJsonTarget {
  [packageKey: string]: {
    dependencies?: { [name: string]: string };
    runtime?: { [dll: string]: object };
  };
}

interface DepsJson {
  runtimeTarget?: { name: string };
  targets?: { [framework: string]: DepsJsonTarget };
  libraries?: {
    [packageKey: string]: {
      type: string;
      serviceable?: boolean;
      sha512?: string;
      path?: string;
      hashPath?: string;
    };
  };
}

// skip packages that are not app dependencies
const NON_APP_TYPES = new Set(["runtimepack", "platform", "runtime"]);

function getLibraryEntry(
  packageName: string,
  version: string | undefined,
  depsJson: DepsJson,
): NonNullable<DepsJson["libraries"]>[string] | undefined {
  const libraries = depsJson.libraries;
  if (!libraries) {
    return undefined;
  }
  if (version) {
    return libraries[`${packageName}/${version}`];
  }
  const lowerName = packageName.toLowerCase();
  for (const [key, lib] of Object.entries(libraries)) {
    const [name] = key.split("/");
    if (name.toLowerCase() === lowerName) {
      return lib;
    }
  }
  return undefined;
}

function isPlatformOrRuntimePackage(
  packageName: string,
  depsJson: DepsJson,
  version?: string,
): boolean {
  const library = getLibraryEntry(packageName, version, depsJson);
  return library !== undefined && NON_APP_TYPES.has(library.type);
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

export async function dotnetFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, content] of Object.entries(filePathToContent)) {
    if (!filePath.endsWith(".deps.json")) {
      continue;
    }

    try {
      const depGraph = buildDepGraphFromDepsJson(content, filePath);
      if (!depGraph) {
        continue;
      }

      const depGraphFact: DepGraphFact = {
        type: "depGraph",
        data: depGraph,
      };
      const testedFilesFact: TestedFilesFact = {
        type: "testedFiles",
        data: [path.basename(filePath)],
      };
      scanResults.push({
        facts: [depGraphFact, testedFilesFact],
        identity: {
          type: "nuget",
          targetFile: filePath,
        },
      });
    } catch (err) {
      debug(
        `Failed to parse .NET deps.json at ${filePath}: ${getErrorMessage(
          err,
        )}`,
      );
    }
  }

  return scanResults;
}

function buildDepGraphFromDepsJson(content: string, filePath: string) {
  const depsJson: DepsJson = JSON.parse(content);

  const targets = depsJson.targets;
  if (!targets) {
    debug(`No targets in deps.json: ${filePath}`);
    return null;
  }

  // Use the runtime target framework, or fall back to the first available
  const runtimeTargetName = depsJson.runtimeTarget?.name;
  const targetKey =
    runtimeTargetName && targets[runtimeTargetName]
      ? runtimeTargetName
      : Object.keys(targets)[0];

  if (!targetKey) {
    return null;
  }

  const target = targets[targetKey];
  const allPackages = Object.keys(target);

  // Find the root project entry (has no "/" in key pattern or matches the app name)
  const rootEntry = allPackages.find((key) => {
    const parsed = parsePackageKey(key);
    if (!parsed) {
      return true;
    }
    // The root project typically has version "1.0.0" and its name matches the deps.json filename
    const depsFileName = path.basename(filePath, ".deps.json");
    return parsed.name.toLowerCase() === depsFileName.toLowerCase();
  });

  let rootName: string;
  let rootVersion: string;
  let rootDependencies: { [name: string]: string } | undefined;

  if (rootEntry) {
    const parsed = parsePackageKey(rootEntry);
    rootName = parsed ? parsed.name : rootEntry;
    rootVersion = parsed ? parsed.version : "0.0.0";
    rootDependencies = target[rootEntry]?.dependencies;
  } else {
    rootName = path.basename(filePath, ".deps.json");
    rootVersion = "0.0.0";
    rootDependencies = undefined;
  }

  const builder = new DepGraphBuilder(
    { name: "nuget" },
    { name: rootName, version: rootVersion },
  );

  // Index all non-framework packages by lowercase name for lookup
  const packageIndex = new Map<
    string,
    { name: string; version: string; dependencies: { [name: string]: string } }
  >();

  for (const key of allPackages) {
    const parsed = parsePackageKey(key);
    if (!parsed) {
      continue;
    }
    if (isPlatformOrRuntimePackage(parsed.name, depsJson, parsed.version)) {
      continue;
    }
    packageIndex.set(parsed.name.toLowerCase(), {
      name: parsed.name,
      version: parsed.version,
      dependencies: target[key]?.dependencies || {},
    });
  }

  if (packageIndex.size === 0) {
    return null;
  }

  const visited = new Set<string>();

  function addDependency(parentNodeId: string, depName: string): void {
    const pkg = packageIndex.get(depName.toLowerCase());
    if (!pkg) {
      return;
    }

    const nodeId = `${pkg.name}@${pkg.version}`;
    if (!visited.has(nodeId)) {
      visited.add(nodeId);
      builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);

      for (const [transitiveName, transitiveVersion] of Object.entries(
        pkg.dependencies,
      )) {
        if (
          !isPlatformOrRuntimePackage(
            transitiveName,
            depsJson,
            transitiveVersion,
          )
        ) {
          addDependency(nodeId, transitiveName);
        }
      }
    }
    builder.connectDep(parentNodeId, nodeId);
  }

  // Add direct dependencies from root
  if (rootDependencies) {
    for (const [depName, depVersion] of Object.entries(rootDependencies)) {
      if (!isPlatformOrRuntimePackage(depName, depsJson, depVersion)) {
        addDependency(builder.rootNodeId, depName);
      }
    }
  } else {
    // No root entry found — add all packages as direct dependencies
    for (const [, pkg] of packageIndex) {
      const nodeId = `${pkg.name}@${pkg.version}`;
      if (!visited.has(nodeId)) {
        visited.add(nodeId);
        builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);
      }
      builder.connectDep(builder.rootNodeId, nodeId);
    }
  }

  return builder.build();
}
