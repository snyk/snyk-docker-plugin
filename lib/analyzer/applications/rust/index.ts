import { DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import { getErrorMessage } from "../../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";
import {
  CargoLockDependency,
  CargoLockPackage,
  parseCargoLock,
} from "./cargo-lock-parser";
import { parseCargoTomlRootPackage } from "./cargo-toml-parser";

const debug = Debug("snyk");

export const DEP_GRAPH_TYPE = "cargo";

type PackageIndex = Map<string, CargoLockPackage>;

function packageNodeId(pkg: { name: string; version: string }): string {
  return `${pkg.name}@${pkg.version}`;
}

function buildPackageIndex(packages: CargoLockPackage[]): PackageIndex {
  const index: PackageIndex = new Map();
  for (const pkg of packages) {
    index.set(packageNodeId(pkg), pkg);
  }
  return index;
}

function resolvePackage(
  dep: CargoLockDependency,
  packages: CargoLockPackage[],
  packageIndex: PackageIndex,
): CargoLockPackage | undefined {
  if (dep.version) {
    return packageIndex.get(`${dep.name}@${dep.version}`);
  }

  const matches = packages.filter((p) => p.name === dep.name);
  if (matches.length === 1) {
    return matches[0];
  }

  return undefined;
}

function determineRootAndDirectDeps(
  packages: CargoLockPackage[],
  lockfilePath: string,
  manifestRoot: { name: string; version: string } | undefined,
): { name: string; version: string; directDeps: CargoLockDependency[] } | null {
  const sourceless = packages.filter((p) => p.source === undefined);

  if (manifestRoot) {
    const rootPkg = packages.find(
      (p) => p.name === manifestRoot.name && p.version === manifestRoot.version,
    );
    return {
      name: manifestRoot.name,
      version: manifestRoot.version,
      directDeps: rootPkg ? rootPkg.dependencies : [],
    };
  }

  if (sourceless.length === 1) {
    return {
      name: sourceless[0].name,
      version: sourceless[0].version,
      directDeps: sourceless[0].dependencies,
    };
  }

  if (sourceless.length > 1) {
    return {
      name: path.basename(path.dirname(lockfilePath)),
      version: "0.0.0",
      directDeps: sourceless.map((p) => ({
        name: p.name,
        version: p.version,
      })),
    };
  }

  return null;
}

async function addDependency(
  parentNodeId: string,
  dep: CargoLockDependency,
  packages: CargoLockPackage[],
  packageIndex: PackageIndex,
  ancestorPath: Set<string>,
  addedNodes: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  const pkg = resolvePackage(dep, packages, packageIndex);
  if (!pkg) {
    debug(
      `Could not resolve Cargo dependency ${dep.name}${
        dep.version ? `@${dep.version}` : ""
      }`,
    );
    return;
  }

  const nodeId = packageNodeId(pkg);

  if (ancestorPath.has(nodeId)) {
    builder.connectDep(parentNodeId, nodeId);
    return;
  }

  if (!addedNodes.has(nodeId)) {
    addedNodes.add(nodeId);
    builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);
  }

  const nextAncestors = new Set(ancestorPath);
  nextAncestors.add(nodeId);

  for (const childDep of pkg.dependencies) {
    await addDependency(
      nodeId,
      childDep,
      packages,
      packageIndex,
      nextAncestors,
      addedNodes,
      builder,
    );
  }

  builder.connectDep(parentNodeId, nodeId);
}

async function buildDepGraphFromCargoLock(
  lockContent: string,
  lockfilePath: string,
  manifestContent: string | undefined,
): Promise<ReturnType<DepGraphBuilder["build"]> | null> {
  const packages = parseCargoLock(lockContent);
  if (packages.length === 0) {
    return null;
  }

  const manifestRoot = manifestContent
    ? parseCargoTomlRootPackage(manifestContent)
    : undefined;

  const root = determineRootAndDirectDeps(packages, lockfilePath, manifestRoot);
  if (!root) {
    return null;
  }

  const builder = new DepGraphBuilder(
    { name: DEP_GRAPH_TYPE },
    { name: root.name, version: root.version },
  );

  const packageIndex = buildPackageIndex(packages);
  const addedNodes = new Set<string>();

  for (const dep of root.directDeps) {
    await addDependency(
      builder.rootNodeId,
      dep,
      packages,
      packageIndex,
      new Set([builder.rootNodeId]),
      addedNodes,
      builder,
    );
  }

  return builder.build();
}

export async function rustFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  const lockfiles = Object.entries(filePathToContent).filter(
    ([filePath]) => path.basename(filePath) === "Cargo.lock",
  );

  for (const [lockfilePath, lockContent] of lockfiles) {
    try {
      const dir = path.dirname(lockfilePath);
      const manifestPath = path.join(dir, "Cargo.toml");
      const manifestContent = filePathToContent[manifestPath];

      const depGraph = await buildDepGraphFromCargoLock(
        lockContent,
        lockfilePath,
        manifestContent,
      );
      if (!depGraph) {
        continue;
      }

      const testedFiles = manifestContent
        ? ["Cargo.toml", "Cargo.lock"]
        : ["Cargo.lock"];

      const depGraphFact: DepGraphFact = {
        type: "depGraph",
        data: depGraph,
      };
      const testedFilesFact: TestedFilesFact = {
        type: "testedFiles",
        data: testedFiles,
      };

      scanResults.push({
        facts: [depGraphFact, testedFilesFact],
        identity: {
          type: DEP_GRAPH_TYPE,
          targetFile: lockfilePath,
        },
      });
    } catch (err) {
      debug(
        `Failed to parse Cargo.lock at ${lockfilePath}: ${getErrorMessage(
          err,
        )}`,
      );
    }
  }

  return scanResults;
}
