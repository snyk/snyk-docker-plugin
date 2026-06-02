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

  const rootEntry = allPackages.find((key) => {
    const parsed = parsePackageKey(key);
    if (!parsed) {
      return true;
    }
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

  // Index all packages by lowercase name
  const packageIndex = new Map<
    string,
    { name: string; version: string; dependencies: { [name: string]: string } }
  >();

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

      for (const transitiveName of Object.keys(pkg.dependencies)) {
        addDependency(nodeId, transitiveName);
      }
    }
    builder.connectDep(parentNodeId, nodeId);
  }

  if (rootDependencies) {
    for (const depName of Object.keys(rootDependencies)) {
      addDependency(builder.rootNodeId, depName);
    }
  } else {
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
