import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import * as TOML from "@iarna/toml";
import { getErrorMessage } from "../../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";

const debug = Debug("snyk");
const PACKAGE_MANAGER_TYPE = "uv";
const UV_LOCK_FILE = "uv.lock";

interface UvPackage {
  name: string;
  version: string;
  // Names of this package's production dependencies (from the `dependencies`
  // array). Dev/group dependencies live in separate tables and are ignored.
  dependencies: string[];
  isProjectRoot: boolean;
}

export async function uvFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const filePath of Object.keys(filePathToContent)) {
    if (path.basename(filePath) !== UV_LOCK_FILE) {
      continue;
    }

    let depGraph: DepGraph | null;
    try {
      depGraph = await buildDepGraphFromUvLock(
        filePathToContent[filePath],
        filePath,
      );
    } catch (err) {
      // Skip a malformed lockfile rather than failing the whole image scan.
      debug(`Failed to parse uv.lock at ${filePath}: ${getErrorMessage(err)}`);
      continue;
    }
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
        type: PACKAGE_MANAGER_TYPE,
        targetFile: filePath,
      },
    });
  }

  return scanResults;
}

async function buildDepGraphFromUvLock(
  content: string,
  lockFilePath: string,
): Promise<DepGraph | null> {
  const packages = parseUvLockPackages(content);
  if (packages.length === 0) {
    return null;
  }

  const packagesByName = new Map<string, UvPackage[]>();
  for (const pkg of packages) {
    const key = pkg.name.toLowerCase();
    if (!packagesByName.has(key)) {
      packagesByName.set(key, []);
    }
    packagesByName.get(key)!.push(pkg);
  }

  const root = findRootPackage(packages);
  if (!root) {
    debug(
      `Could not determine the root project package in ${lockFilePath}; skipping`,
    );
    return null;
  }

  const builder = new DepGraphBuilder(
    { name: PACKAGE_MANAGER_TYPE },
    { name: root.name, version: root.version },
  );
  const visited = new Set<string>();

  for (const dependencyName of root.dependencies) {
    await addDependencyToDepGraph(
      builder.rootNodeId,
      dependencyName,
      root,
      packagesByName,
      visited,
      builder,
    );
  }

  const depGraph = builder.build();
  if (depGraph.getDepPkgs().length === 0) {
    return null;
  }

  return depGraph;
}

async function addDependencyToDepGraph(
  parentNodeId: string,
  dependencyName: string,
  root: UvPackage,
  packagesByName: Map<string, UvPackage[]>,
  visited: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  const matches = packagesByName.get(dependencyName.toLowerCase());
  if (!matches) {
    return;
  }

  for (const pkg of matches) {
    // The root project is already the graph root; don't re-add it as a child
    // even if another package declares a dependency on it.
    if (pkg === root) {
      continue;
    }

    const nodeId = `${pkg.name}@${pkg.version}`;
    if (!visited.has(nodeId)) {
      visited.add(nodeId);
      builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);

      for (const childName of pkg.dependencies) {
        await addDependencyToDepGraph(
          nodeId,
          childName,
          root,
          packagesByName,
          visited,
          builder,
        );
      }
    }
    builder.connectDep(parentNodeId, nodeId);
  }
}

// uv.lock is a TOML file with an array of [[package]] tables. Each package has a
// name, version, optional `source`, and an optional `dependencies` array of
// inline tables shaped like `{ name = "x" }` (sometimes with `marker`/`extra`).
function parseUvLockPackages(content: string): UvPackage[] {
  const parsed = TOML.parse(content) as {
    package?: Array<{
      name?: unknown;
      version?: unknown;
      source?: unknown;
      dependencies?: unknown;
    }>;
  };

  const rawPackages = Array.isArray(parsed.package) ? parsed.package : [];
  const packages: UvPackage[] = [];

  for (const rawPackage of rawPackages) {
    if (!rawPackage || typeof rawPackage.name !== "string") {
      continue;
    }

    packages.push({
      name: rawPackage.name,
      version: typeof rawPackage.version === "string" ? rawPackage.version : "",
      dependencies: parseDependencyNames(rawPackage.dependencies),
      isProjectRoot: isProjectRootSource(rawPackage.source),
    });
  }

  return packages;
}

function parseDependencyNames(dependencies: unknown): string[] {
  if (!Array.isArray(dependencies)) {
    return [];
  }
  const names: string[] = [];
  for (const dependency of dependencies) {
    if (
      dependency &&
      typeof dependency === "object" &&
      typeof (dependency as { name?: unknown }).name === "string"
    ) {
      names.push((dependency as { name: string }).name);
    }
  }
  return names;
}

// The project's own package(s) are written with an `editable` or `virtual`
// source pointing at the workspace (e.g. `source = { editable = "." }`).
function isProjectRootSource(source: unknown): boolean {
  return (
    !!source &&
    typeof source === "object" &&
    ("editable" in source || "virtual" in source)
  );
}

function findRootPackage(packages: UvPackage[]): UvPackage | null {
  const roots = packages.filter((pkg) => pkg.isProjectRoot);
  if (roots.length === 1) {
    return roots[0];
  }

  // Fallback for lockfiles without an editable/virtual marker: the root is the
  // only package that nothing else depends on. If this is ambiguous (e.g. a
  // workspace with multiple members), bail out rather than guess.
  const referenced = new Set<string>();
  for (const pkg of packages) {
    for (const dependencyName of pkg.dependencies) {
      referenced.add(dependencyName.toLowerCase());
    }
  }
  const sinks = packages.filter(
    (pkg) => !referenced.has(pkg.name.toLowerCase()),
  );
  if (sinks.length === 1) {
    return sinks[0];
  }

  return null;
}
