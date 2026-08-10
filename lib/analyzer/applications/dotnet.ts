import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import { getErrorMessage } from "../../error-utils";
import {
  DotnetGraphParseResult,
  DotnetPackage,
  parsePackagesConfig,
  parsePackagesLockJson,
  parseProjectAssetsJson,
  parseProjectFile,
} from "../../dotnet-parser";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const PACKAGE_MANAGER_TYPE = "nuget";

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
  dependencies: string[];
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

    for (const childName of pkg.dependencies) {
      await addDependency(nodeId, childName, packageIndex, visited, builder);
    }
  }
  builder.connectDep(parentNodeId, nodeId);
}

async function buildDepGraphFromPackageIndex(
  packageIndex: PackageIndex,
  directDependencyNames: string[],
  rootName: string,
  rootVersion: string,
): Promise<DepGraph> {
  const builder = new DepGraphBuilder(
    { name: PACKAGE_MANAGER_TYPE },
    { name: rootName, version: rootVersion },
  );

  const visited = new Set<string>();
  for (const depName of directDependencyNames) {
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

export async function dotnetFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, content] of Object.entries(filePathToContent)) {
    if (!filePath.replace(/\\/g, "/").endsWith(".deps.json")) {
      continue;
    }

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
          type: PACKAGE_MANAGER_TYPE,
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

  scanResults.push(
    ...(await newFormatDotnetFilesToScannedProjects(filePathToContent)),
  );

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
      dependencies: Object.keys(target[key]?.dependencies || {}),
    });
  }

  const directDeps = Object.keys(rootDependencies);

  return buildDepGraphFromPackageIndex(
    packageIndex,
    directDeps,
    rootName,
    rootVersion,
  );
}

interface DotnetNewFormatProjectFiles {
  projectAssetsJson?: string;
  packagesLockJson?: string;
  packagesConfig?: string;
  projectFile?: string;
}

function normalizeSlashes(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

// Groups the new manifest/lockfile formats by project root so a directory
// holding more than one of them (e.g. packages.config next to a .csproj)
// contributes a single scan result rather than double-counting the project.
// obj/project.assets.json belongs to the directory above obj/, mirroring
// where `dotnet restore` writes it relative to the project file.
function groupNewFormatFilesByProjectRoot(
  filePathToContent: FilePathToContent,
): Map<string, DotnetNewFormatProjectFiles> {
  const projects = new Map<string, DotnetNewFormatProjectFiles>();

  function projectFor(root: string): DotnetNewFormatProjectFiles {
    let project = projects.get(root);
    if (!project) {
      project = {};
      projects.set(root, project);
    }
    return project;
  }

  for (const filePath of Object.keys(filePathToContent)) {
    const normalized = normalizeSlashes(filePath);
    const fileName = path.posix.basename(normalized);

    if (fileName === "project.assets.json") {
      const objDir = path.posix.dirname(normalized);
      const root = path.posix.dirname(objDir);
      projectFor(root).projectAssetsJson = filePath;
    } else if (fileName === "packages.lock.json") {
      projectFor(path.posix.dirname(normalized)).packagesLockJson = filePath;
    } else if (fileName === "packages.config") {
      projectFor(path.posix.dirname(normalized)).packagesConfig = filePath;
    } else if (
      normalized.endsWith(".csproj") ||
      normalized.endsWith(".fsproj") ||
      normalized.endsWith(".vbproj")
    ) {
      projectFor(path.posix.dirname(normalized)).projectFile = filePath;
    }
  }

  return projects;
}

// deps.json is the fully-resolved publish output; if one exists at or under
// a project root, that root's manifest/lockfile is a duplicate view of the
// same project and is suppressed so it isn't reported twice under two
// differently-resolved graphs.
function isProjectRootCoveredByDepsJson(
  root: string,
  depsJsonPaths: string[],
): boolean {
  const prefix = root.endsWith("/") ? root : `${root}/`;
  return depsJsonPaths.some((depsJsonPath) => depsJsonPath.startsWith(prefix));
}

function buildDepGraphFromFlatPackages(
  packages: DotnetPackage[],
  targetFile: string,
): DepGraph {
  const builder = new DepGraphBuilder(
    { name: PACKAGE_MANAGER_TYPE },
    { name: targetFile },
  );

  for (const pkg of packages) {
    const nodeId = `${pkg.name}@${pkg.version}`;
    builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);
    builder.connectDep(builder.rootNodeId, nodeId);
  }

  return builder.build();
}

function buildScanResultFromFlatPackages(
  packages: DotnetPackage[],
  targetFile: string,
): AppDepsScanResultWithoutTarget | undefined {
  if (packages.length === 0) {
    return undefined;
  }

  const depGraphFact: DepGraphFact = {
    type: "depGraph",
    data: buildDepGraphFromFlatPackages(packages, targetFile),
  };
  const testedFilesFact: TestedFilesFact = {
    type: "testedFiles",
    data: [path.basename(targetFile)],
  };

  return {
    facts: [depGraphFact, testedFilesFact],
    identity: {
      type: PACKAGE_MANAGER_TYPE,
      targetFile,
    },
  };
}

async function buildScanResultFromGraphResult(
  result: DotnetGraphParseResult,
  targetFile: string,
): Promise<AppDepsScanResultWithoutTarget> {
  const packageIndex: PackageIndex = new Map();
  for (const pkg of result.packages) {
    const name = normalizePackageName(pkg.name);
    packageIndex.set(name.toLowerCase(), {
      name,
      version: pkg.version,
      dependencies: pkg.dependencies,
    });
  }

  const depGraph = await buildDepGraphFromPackageIndex(
    packageIndex,
    result.directDependencies,
    result.rootName,
    result.rootVersion,
  );

  const depGraphFact: DepGraphFact = {
    type: "depGraph",
    data: depGraph,
  };
  const testedFilesFact: TestedFilesFact = {
    type: "testedFiles",
    data: [path.basename(targetFile)],
  };

  return {
    facts: [depGraphFact, testedFilesFact],
    identity: {
      type: PACKAGE_MANAGER_TYPE,
      targetFile,
    },
  };
}

// Picks the richest available resolution per project root: fully-resolved
// restore output beats a flat lockfile, which beats a flat manifest with no
// transitive data at all.
async function newFormatDotnetFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const projects = groupNewFormatFilesByProjectRoot(filePathToContent);
  if (projects.size === 0) {
    return scanResults;
  }

  const depsJsonPaths = Object.keys(filePathToContent)
    .map(normalizeSlashes)
    .filter((filePath) => filePath.endsWith(".deps.json"));

  for (const [root, project] of projects.entries()) {
    if (isProjectRootCoveredByDepsJson(root, depsJsonPaths)) {
      continue;
    }

    try {
      if (project.projectAssetsJson) {
        const result = parseProjectAssetsJson(
          filePathToContent[project.projectAssetsJson],
        );
        if (result) {
          scanResults.push(
            await buildScanResultFromGraphResult(
              result,
              project.projectAssetsJson,
            ),
          );
        }
        continue;
      }

      if (project.packagesLockJson) {
        const result = parsePackagesLockJson(
          filePathToContent[project.packagesLockJson],
        );
        if (result) {
          scanResults.push(
            await buildScanResultFromGraphResult(
              result,
              project.packagesLockJson,
            ),
          );
        }
        continue;
      }

      if (project.packagesConfig) {
        const packages = parsePackagesConfig(
          filePathToContent[project.packagesConfig],
        );
        const result = buildScanResultFromFlatPackages(
          packages,
          project.packagesConfig,
        );
        if (result) {
          scanResults.push(result);
        }
        continue;
      }

      if (project.projectFile) {
        const packages = parseProjectFile(
          filePathToContent[project.projectFile],
        );
        const result = buildScanResultFromFlatPackages(
          packages,
          project.projectFile,
        );
        if (result) {
          scanResults.push(result);
        }
      }
    } catch (err) {
      debug(
        `Failed to parse .NET NuGet manifest under ${root}: ${getErrorMessage(
          err,
        )}`,
      );
    }
  }

  return scanResults;
}
