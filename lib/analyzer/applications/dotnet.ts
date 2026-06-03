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

function addDependency(
  parentNodeId: string,
  depName: string,
  packageIndex: PackageIndex,
  visited: Set<string>,
  builder: DepGraphBuilder,
): void {
  const pkg = packageIndex.get(depName.toLowerCase());
  if (!pkg) {
    return;
  }

  const nodeId = `${pkg.name}@${pkg.version}`;
  if (!visited.has(nodeId)) {
    visited.add(nodeId);
    builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);

    for (const childName of Object.keys(pkg.dependencies)) {
      addDependency(nodeId, childName, packageIndex, visited, builder);
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
    packageIndex.set(parsed.name.toLowerCase(), {
      name: parsed.name,
      version: parsed.version,
      dependencies: target[key]?.dependencies || {},
    });
  }

  const visited = new Set<string>();
  const directDeps = Object.keys(rootDependencies);

  for (const depName of directDeps) {
    addDependency(builder.rootNodeId, depName, packageIndex, visited, builder);
  }

  return builder.build();
}
