import { DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import { getErrorMessage } from "../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const debug = Debug("snyk");

interface DepsJsonTarget {
  [packageKey: string]: {
    dependencies?: { [name: string]: string };
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

interface PackageInfo {
  name: string;
  version: string;
  dependencies: { [name: string]: string };
}

type PackageIndex = Map<string, PackageInfo>;

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

// Self-contained .NET publishes prefix the bundled runtime packages with
// "runtimepack." in deps.json (e.g. runtimepack.Microsoft.NETCore.App.Runtime.linux-x64).
// The canonical NuGet id (which the vuln DB matches against) has no prefix, so
// strip it to keep names matchable. See https://github.com/dotnet/sdk/issues/3010
const RUNTIME_PACK_PREFIX = "runtimepack.";

function normalizePackageName(name: string): string {
  return name.startsWith(RUNTIME_PACK_PREFIX)
    ? name.slice(RUNTIME_PACK_PREFIX.length)
    : name;
}

async function addDependency(
  parentNodeId: string,
  depName: string,
  packageIndex: PackageIndex,
  visited: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  const pkg = packageIndex.get(normalizePackageName(depName).toLowerCase());
  if (!pkg) {
    return;
  }

  const nodeId = `${pkg.name}@${pkg.version}`;
  if (!visited.has(nodeId)) {
    visited.add(nodeId);
    builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);

    for (const childName of Object.keys(pkg.dependencies)) {
      await addDependency(nodeId, childName, packageIndex, visited, builder);
    }
  }
  builder.connectDep(parentNodeId, nodeId);
}

export async function dotnetFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, content] of Object.entries(filePathToContent)) {
    try {
      const depGraph = await buildDepGraphFromDepsJson(content, filePath);
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

async function buildDepGraphFromDepsJson(content: string, filePath: string) {
  const depsJson: DepsJson = JSON.parse(content);

  const targets = depsJson.targets;
  if (!targets) {
    debug(`No targets in deps.json: ${filePath}`);
    return null;
  }

  const target = depsJson.runtimeTarget?.name
    ? targets[depsJson.runtimeTarget.name]
    : undefined;
  if (!target) {
    return null;
  }

  const libraries = depsJson.libraries;
  if (!libraries) {
    return null;
  }

  const allPackages = Object.keys(target);

  const rootEntry = allPackages.find((key) => {
    const lib = libraries[key];
    return lib?.type === "project";
  });
  if (!rootEntry) {
    return null;
  }

  const parsed = parsePackageKey(rootEntry);
  const rootName = parsed ? parsed.name : rootEntry;
  const rootVersion = parsed ? parsed.version : "0.0.0";
  const rootDependencies = target[rootEntry]?.dependencies;
  if (!rootDependencies) {
    return null;
  }

  const builder = new DepGraphBuilder(
    { name: "nuget" },
    { name: rootName, version: rootVersion },
  );

  const packageIndex: PackageIndex = new Map();
  for (const key of allPackages) {
    const parsed = parsePackageKey(key);
    if (!parsed) {
      continue;
    }
    const name = normalizePackageName(parsed.name);
    packageIndex.set(name.toLowerCase(), {
      name,
      version: parsed.version,
      dependencies: target[key]?.dependencies || {},
    });
  }

  const visited = new Set<string>();
  const directDeps = Object.keys(rootDependencies);

  for (const depName of directDeps) {
    await addDependency(
      builder.rootNodeId,
      depName,
      packageIndex,
      visited,
      builder,
    );
  }

  return builder.build();
}
