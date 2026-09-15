// Rust application dependency scanning is manifest+lockfile only.
// Compiled Rust binaries are deliberately not fingerprinted: unlike Go binaries,
// Rust ELF artifacts carry no embedded build-info section (see lib/go-parser),
// so there is nothing to read out of a binary for dependency discovery.

import { DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import * as path from "path";
import { eventLoopSpinner } from "event-loop-spinner";
import { DepGraphFact, TestedFilesFact } from "../../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";
import {
  CargoLockPackage,
  parseCargoLock,
  parseDependencyRef,
  resolveDependencyPackage,
} from "./cargo-lock-parser";

const debug = Debug("snyk-docker-plugin:rust");

interface LockManifestPair {
  lockPath: string;
  manifestPath?: string;
}

export async function cargoFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  const pairs = findLockManifestPairs(filePathToContent);

  for (const pair of pairs) {
    try {
      const lockContent = filePathToContent[pair.lockPath];
      const manifestContent = pair.manifestPath
        ? filePathToContent[pair.manifestPath]
        : undefined;

      const depGraph = await buildDepGraphFromCargoLock(
        lockContent,
        manifestContent,
      );
      if (!depGraph) {
        continue;
      }

      const testedFiles = pair.manifestPath
        ? ["Cargo.lock", "Cargo.toml"]
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
          type: depGraph.pkgManager.name,
          targetFile: pair.lockPath,
        },
      });
    } catch (err) {
      debug(`Failed to parse Cargo.lock at ${pair.lockPath}: ${err}`);
    }
  }

  return scanResults;
}

function findLockManifestPairs(
  filePathToContent: FilePathToContent,
): LockManifestPair[] {
  const pairs: LockManifestPair[] = [];
  const lockPaths = Object.keys(filePathToContent).filter(
    (filePath) => path.basename(filePath) === "Cargo.lock",
  );

  for (const lockPath of lockPaths) {
    const directory = path.dirname(lockPath);
    const manifestPath = path.join(directory, "Cargo.toml");
    pairs.push({
      lockPath,
      manifestPath: filePathToContent[manifestPath] ? manifestPath : undefined,
    });
  }

  return pairs;
}

function parsePackageNameFromManifest(content: string): string | undefined {
  const lines = content.split(/\r?\n/);
  let inPackageSection = false;

  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (line.startsWith("[") && line.endsWith("]")) {
      inPackageSection = line === "[package]";
      continue;
    }
    if (inPackageSection && line.startsWith("name")) {
      const eqIndex = line.indexOf("=");
      if (eqIndex === -1) {
        continue;
      }
      const value = line.slice(eqIndex + 1).trim();
      if (value.startsWith('"') && value.endsWith('"')) {
        return value.slice(1, -1).replace(/\\"/g, '"');
      }
      if (value.startsWith("'") && value.endsWith("'")) {
        return value.slice(1, -1).replace(/''/g, "'");
      }
    }
  }

  return undefined;
}

function findDerivedRootPackage(
  packages: CargoLockPackage[],
): CargoLockPackage | undefined {
  const withoutSource = packages.filter((p) => !p.source);
  if (withoutSource.length === 1) {
    return withoutSource[0];
  }

  const referenced = new Set<string>();
  for (const pkg of packages) {
    for (const dep of pkg.dependencies) {
      const ref = parseDependencyRef(dep);
      const resolved = resolveDependencyPackage(ref, packages);
      if (resolved) {
        referenced.add(`${resolved.name}@${resolved.version}`);
      }
    }
  }

  const unreferenced = packages.filter(
    (p) => !referenced.has(`${p.name}@${p.version}`),
  );
  if (unreferenced.length === 1) {
    return unreferenced[0];
  }

  return packages[0];
}

async function buildDepGraphFromCargoLock(
  lockContent: string,
  manifestContent?: string,
) {
  if (!lockContent || !lockContent.trim()) {
    return null;
  }

  let parsed;
  try {
    parsed = parseCargoLock(lockContent);
  } catch {
    return null;
  }

  if (parsed.packages.length === 0) {
    return null;
  }

  let rootPackage: CargoLockPackage | undefined;
  let rootName: string;
  let rootVersion: string;

  if (manifestContent) {
    const manifestName = parsePackageNameFromManifest(manifestContent);
    if (manifestName) {
      rootPackage = parsed.packages.find((p) => p.name === manifestName);
      rootName = manifestName;
      rootVersion = rootPackage?.version || "0.0.0";
    } else {
      rootPackage = findDerivedRootPackage(parsed.packages);
      rootName = rootPackage?.name || "unknown";
      rootVersion = rootPackage?.version || "0.0.0";
    }
  } else {
    rootPackage = findDerivedRootPackage(parsed.packages);
    rootName = rootPackage?.name || "unknown";
    rootVersion = rootPackage?.version || "0.0.0";
  }

  const builder = new DepGraphBuilder(
    { name: "cargo" },
    { name: rootName, version: rootVersion },
  );

  const visited = new Set<string>();
  const rootDeps = rootPackage?.dependencies || [];

  for (const dep of rootDeps) {
    await addDependency(
      builder.rootNodeId,
      dep,
      parsed.packages,
      visited,
      builder,
    );
  }

  return builder.build();
}

async function addDependency(
  parentNodeId: string,
  depString: string,
  packages: CargoLockPackage[],
  visited: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  const depRef = parseDependencyRef(depString);
  const pkg = resolveDependencyPackage(depRef, packages);
  if (!pkg) {
    return;
  }

  const nodeId = `${pkg.name}@${pkg.version}`;
  if (!visited.has(nodeId)) {
    visited.add(nodeId);
    builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);

    for (const childDep of pkg.dependencies) {
      await addDependency(nodeId, childDep, packages, visited, builder);
    }
  }
  builder.connectDep(parentNodeId, nodeId);
}
