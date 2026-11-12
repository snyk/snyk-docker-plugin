import { DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import { getErrorMessage } from "../../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";
import {
  CargoDependencyRef,
  CargoLock,
  CargoPackage,
  parseCargoLock,
} from "./cargo-lock-parser";

const debug = Debug("snyk-docker-plugin:rust:cargo");

type PackageIndex = Map<string, CargoPackage[]>;

function nodeId(pkg: { name: string; version: string }): string {
  return `${pkg.name}@${pkg.version}`;
}

function buildPackageIndex(packages: CargoPackage[]): PackageIndex {
  const index: PackageIndex = new Map();
  for (const pkg of packages) {
    const existing = index.get(pkg.name) ?? [];
    existing.push(pkg);
    index.set(pkg.name, existing);
  }
  return index;
}

function resolveDepRef(
  depRef: CargoDependencyRef,
  packageIndex: PackageIndex,
): CargoPackage[] {
  const candidates = packageIndex.get(depRef.name) ?? [];
  if (depRef.version !== undefined) {
    return candidates.filter((pkg) => pkg.version === depRef.version);
  }
  if (candidates.length === 1) {
    return candidates;
  }
  if (candidates.length > 1) {
    debug(
      "ambiguous Cargo dependency %s in lockfile; connecting all %d candidates",
      depRef.name,
      candidates.length,
    );
    return candidates;
  }
  return [];
}

function computeInDegreeZeroPackages(
  packages: CargoPackage[],
  packageIndex: PackageIndex,
): CargoPackage[] {
  const dependedOn = new Set<string>();
  for (const pkg of packages) {
    for (const depRef of pkg.dependencies) {
      for (const resolved of resolveDepRef(depRef, packageIndex)) {
        dependedOn.add(nodeId(resolved));
      }
    }
  }
  return packages.filter((pkg) => !dependedOn.has(nodeId(pkg)));
}

function syntheticRootName(filePath: string): string {
  return path.basename(path.dirname(filePath)) || "rust-app";
}

async function addDependency(
  parentNodeId: string,
  depRef: CargoDependencyRef,
  packageIndex: PackageIndex,
  visited: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  const targets = resolveDepRef(depRef, packageIndex);
  for (const pkg of targets) {
    const pkgNodeId = nodeId(pkg);
    if (!visited.has(pkgNodeId)) {
      visited.add(pkgNodeId);
      builder.addPkgNode({ name: pkg.name, version: pkg.version }, pkgNodeId);
      for (const childRef of pkg.dependencies) {
        await addDependency(
          pkgNodeId,
          childRef,
          packageIndex,
          visited,
          builder,
        );
      }
    }
    builder.connectDep(parentNodeId, pkgNodeId);
  }
}

async function attachUnvisitedPackages(
  packages: CargoPackage[],
  rootPkg: { name: string; version: string },
  isLocalRoot: boolean,
  visited: Set<string>,
  builder: DepGraphBuilder,
  packageIndex: PackageIndex,
): Promise<void> {
  for (const pkg of packages) {
    if (
      isLocalRoot &&
      pkg.name === rootPkg.name &&
      pkg.version === rootPkg.version
    ) {
      continue;
    }

    const pkgNodeId = nodeId(pkg);
    if (visited.has(pkgNodeId)) {
      continue;
    }

    visited.add(pkgNodeId);
    builder.addPkgNode({ name: pkg.name, version: pkg.version }, pkgNodeId);
    builder.connectDep(builder.rootNodeId, pkgNodeId);
    for (const depRef of pkg.dependencies) {
      await addDependency(pkgNodeId, depRef, packageIndex, visited, builder);
    }
  }
}

async function buildDepGraphFromCargoLock(
  content: string,
  filePath: string,
): Promise<ReturnType<DepGraphBuilder["build"]> | null> {
  const cargoLock: CargoLock = parseCargoLock(content);
  const { packages } = cargoLock;
  if (packages.length === 0) {
    return null;
  }

  const packageIndex = buildPackageIndex(packages);
  const localPackages = packages.filter((pkg) => pkg.source === undefined);
  const syntheticRoot = {
    name: syntheticRootName(filePath),
    version: "0.0.0",
  };

  let rootPkg: { name: string; version: string };
  let initialDepRefs: CargoDependencyRef[];
  let isLocalRoot = false;

  if (localPackages.length === 1) {
    const localRoot = localPackages[0];
    rootPkg = { name: localRoot.name, version: localRoot.version };
    initialDepRefs = localRoot.dependencies;
    isLocalRoot = true;
  } else if (localPackages.length > 1) {
    rootPkg = syntheticRoot;
    initialDepRefs = localPackages.map((pkg) => ({
      name: pkg.name,
      version: pkg.version,
    }));
  } else {
    rootPkg = syntheticRoot;
    let entryPackages = computeInDegreeZeroPackages(packages, packageIndex);
    if (entryPackages.length === 0) {
      entryPackages = packages;
    }
    initialDepRefs = entryPackages.map((pkg) => ({
      name: pkg.name,
      version: pkg.version,
    }));
  }

  const builder = new DepGraphBuilder({ name: "cargo" }, rootPkg);
  const visited = new Set<string>();

  for (const depRef of initialDepRefs) {
    await addDependency(
      builder.rootNodeId,
      depRef,
      packageIndex,
      visited,
      builder,
    );
  }

  await attachUnvisitedPackages(
    packages,
    rootPkg,
    isLocalRoot,
    visited,
    builder,
    packageIndex,
  );

  return builder.build();
}

export async function cargoFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, content] of Object.entries(filePathToContent)) {
    if (path.basename(filePath) !== "Cargo.lock") {
      continue;
    }

    try {
      const depGraph = await buildDepGraphFromCargoLock(content, filePath);
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
          type: "cargo",
          targetFile: filePath,
        },
      });
    } catch (err) {
      debug(
        `Failed to parse Cargo.lock at ${filePath}: ${getErrorMessage(err)}`,
      );
    }
  }

  return scanResults;
}
