import { DepGraph, legacy } from "@snyk/dep-graph";
import * as Debug from "debug";
import * as path from "path";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import * as resolveDeps from "snyk-resolve-deps";
import { DepGraphFact, TestedFilesFact } from "../../facts";

const debug = Debug("snyk");

import { InvalidUserInputError } from "@snyk/composer-lockfile-parser/dist/errors";
import {
  getNpmLockfileVersion,
  getPnpmLockfileVersion,
  getYarnLockfileVersion,
  LockfileType,
  NodeLockfileVersion,
} from "snyk-nodejs-lockfile-parser";
import { LogicalRoot } from "snyk-resolve-deps/dist/types";
import {
  cleanupAppNodeModules,
  groupNodeAppFilesByDirectory,
  groupNodeModulesFilesByDirectory,
  persistNodeModules,
} from "./node-modules-utils";
import {
  AppDepsScanResultWithoutTarget,
  FilePathToContent,
  FilesByDirMap,
} from "./types";

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
  lockType: lockFileParser.LockfileType;
}

export async function nodeFilesToScannedProjects(
  filePathToContent: FilePathToContent,
  shouldIncludeNodeModules: boolean,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  /**
   * TODO: Add support for Yarn workspaces!
   * https://github.com/snyk/nodejs-lockfile-parser/blob/af8ba81930e950156b539281ecf41c1bc63dacf4/test/lib/yarn-workflows.test.ts#L7-L17
   *
   * When building the ScanResult ensure the workspace is stored in scanResult.identity.args:
   * args: {
   *   rootWorkspace: <path-of-workspace>,
   * };
   */

  if (Object.keys(filePathToContent).length === 0) {
    return [];
  }

  const fileNamesGroupedByDirectory =
    groupNodeAppFilesByDirectory(filePathToContent);
  const manifestFilePairs = findManifestLockPairsInSameDirectory(
    fileNamesGroupedByDirectory,
  );

  if (manifestFilePairs.length !== 0) {
    scanResults.push(
      ...(await depGraphFromManifestFiles(
        filePathToContent,
        manifestFilePairs,
      )),
    );
  }

  if (shouldIncludeNodeModules) {
    const appNodeModulesGroupedByDirectory =
      groupNodeModulesFilesByDirectory(filePathToContent);
    const nodeProjects = findManifestNodeModulesFilesInSameDirectory(
      appNodeModulesGroupedByDirectory,
    );
    if (nodeProjects.length !== 0) {
      scanResults.push(
        ...(await depGraphFromNodeModules(
          filePathToContent,
          nodeProjects,
          appNodeModulesGroupedByDirectory,
        )),
      );
    }
  }

  return scanResults;
}

async function depGraphFromNodeModules(
  filePathToContent: FilePathToContent,
  nodeProjects: string[],
  fileNamesGroupedByDirectory: FilesByDirMap,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  for (const project of nodeProjects) {
    const { tempDir, tempProjectPath, manifestPath } = await persistNodeModules(
      project,
      filePathToContent,
      fileNamesGroupedByDirectory,
    );

    if (!tempDir) {
      continue;
    }

    if (!tempProjectPath) {
      await cleanupAppNodeModules(tempDir);
      continue;
    }

    try {
      const pkgTree: lockFileParser.PkgTree = await resolveDeps(
        tempProjectPath,
        {
          dev: false,
          noFromArrays: true,
        },
      );

      if ((pkgTree as LogicalRoot).numDependencies === 0) {
        continue;
      }

      const depGraph = await legacy.depTreeToGraph(
        pkgTree,
        pkgTree.type || "npm",
      );

      scanResults.push({
        facts: [
          {
            type: "depGraph",
            data: depGraph,
          },
          {
            type: "testedFiles",
            data: manifestPath
              ? manifestPath
              : path.join(project, "node_modules"),
          },
        ],
        identity: {
          type: depGraph.pkgManager.name,
          targetFile: manifestPath
            ? manifestPath
            : path.join(project, "node_modules"),
        },
      });
    } catch (error) {
      debug(
        `An error occurred while analysing node_modules dir: ${error.message}`,
      );
    } finally {
      await cleanupAppNodeModules(tempDir);
    }
  }
  return scanResults;
}

async function depGraphFromManifestFiles(
  filePathToContent: FilePathToContent,
  manifestFilePairs: ManifestLockPathPair[],
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  const shouldIncludeDevDependencies = false;
  const shouldBeStrictForManifestAndLockfileOutOfSync = false;

  for (const pathPair of manifestFilePairs) {
    let depGraph: DepGraph;
    try {
      const lockfileVersion = getLockFileVersion(
        pathPair.lock,
        filePathToContent[pathPair.lock],
      );
      depGraph = shouldBuildDepTree(lockfileVersion)
        ? await buildDepGraphFromDepTree(
            filePathToContent[pathPair.manifest],
            filePathToContent[pathPair.lock],
            pathPair.lockType,
            shouldIncludeDevDependencies,
            shouldBeStrictForManifestAndLockfileOutOfSync,
          )
        : await buildDepGraph(
            filePathToContent[pathPair.manifest],
            filePathToContent[pathPair.lock],
            lockfileVersion,
            shouldIncludeDevDependencies,
            shouldBeStrictForManifestAndLockfileOutOfSync,
          );
    } catch (err) {
      debug(
        `An error occurred while analysing a pair of manifest and lock files: ${err.message}`,
      );
      continue;
    }

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph,
    };
    const testedFilesFact: TestedFilesFact = {
      type: "testedFiles",
      data: [path.basename(pathPair.manifest), path.basename(pathPair.lock)],
    };
    scanResults.push({
      facts: [depGraphFact, testedFilesFact],
      identity: {
        type: depGraph.pkgManager.name,
        targetFile: pathPair.manifest,
      },
    });
  }
  return scanResults;
}

function findManifestLockPairsInSameDirectory(
  fileNamesGroupedByDirectory: FilesByDirMap,
): ManifestLockPathPair[] {
  const manifestLockPathPairs: ManifestLockPathPair[] = [];

  for (const directoryPath of fileNamesGroupedByDirectory.keys()) {
    if (directoryPath.includes("node_modules")) {
      continue;
    }
    const filesInDirectory = fileNamesGroupedByDirectory.get(directoryPath);
    if (!filesInDirectory || filesInDirectory.size < 1) {
      // missing manifest files
      continue;
    }

    const expectedManifest = path.join(directoryPath, "package.json");
    const expectedNpmLockFile = path.join(directoryPath, "package-lock.json");
    const expectedYarnLockFile = path.join(directoryPath, "yarn.lock");

    const hasManifestFile = filesInDirectory.has(expectedManifest);
    const hasLockFile =
      filesInDirectory.has(expectedNpmLockFile) ||
      filesInDirectory.has(expectedYarnLockFile);

    if (hasManifestFile && hasLockFile) {
      manifestLockPathPairs.push({
        manifest: expectedManifest,
        // TODO: correlate filtering action with expected lockfile types
        lock: filesInDirectory.has(expectedNpmLockFile)
          ? expectedNpmLockFile
          : expectedYarnLockFile,
        lockType: filesInDirectory.has(expectedNpmLockFile)
          ? lockFileParser.LockfileType.npm
          : lockFileParser.LockfileType.yarn,
      });
    }
  }

  return manifestLockPathPairs;
}

function findManifestNodeModulesFilesInSameDirectory(
  fileNamesGroupedByDirectory: FilesByDirMap,
): string[] {
  const nodeProjects: string[] = [];

  for (const directoryPath of fileNamesGroupedByDirectory.keys()) {
    const filesInDirectory = fileNamesGroupedByDirectory.get(directoryPath);
    if (!filesInDirectory || filesInDirectory.size < 1) {
      // missing manifest files
      continue;
    }

    const expectedManifest = path.join(directoryPath, "package.json");
    const expectedNpmLockFile = path.join(directoryPath, "package-lock.json");
    const expectedYarnLockFile = path.join(directoryPath, "yarn.lock");

    const hasManifestFile = filesInDirectory.has(expectedManifest);
    const hasLockFile =
      filesInDirectory.has(expectedNpmLockFile) ||
      filesInDirectory.has(expectedYarnLockFile);

    if (hasManifestFile && hasLockFile) {
      continue;
    }
    nodeProjects.push(directoryPath);
  }

  return nodeProjects;
}

function stripUndefinedLabels(
  parserResult: lockFileParser.PkgTree,
): lockFileParser.PkgTree {
  const optionalLabels = parserResult.labels;
  const mandatoryLabels: Record<string, string> = {};
  if (optionalLabels) {
    for (const currentLabelName of Object.keys(optionalLabels)) {
      if (optionalLabels[currentLabelName] !== undefined) {
        mandatoryLabels[currentLabelName] = optionalLabels[currentLabelName]!;
      }
    }
  }
  const parserResultWithProperLabels = Object.assign({}, parserResult, {
    labels: mandatoryLabels,
  });
  return parserResultWithProperLabels;
}

async function buildDepGraph(
  manifestFileContents: string,
  lockFileContents: string,
  lockfileVersion: NodeLockfileVersion,
  shouldIncludeDevDependencies: boolean,
  shouldBeStrictForManifestAndLockfileOutOfSync: boolean,
): Promise<DepGraph> {
  switch (lockfileVersion) {
    case NodeLockfileVersion.YarnLockV1:
      return await lockFileParser.parseYarnLockV1Project(
        manifestFileContents,
        lockFileContents,
        {
          includeDevDeps: shouldIncludeDevDependencies,
          includeOptionalDeps: true,
          includePeerDeps: false,
          pruneLevel: "withinTopLevelDeps",
          strictOutOfSync: shouldBeStrictForManifestAndLockfileOutOfSync,
        },
      );
    case NodeLockfileVersion.YarnLockV2:
      return await lockFileParser.parseYarnLockV2Project(
        manifestFileContents,
        lockFileContents,
        {
          includeDevDeps: shouldIncludeDevDependencies,
          includeOptionalDeps: true,
          pruneWithinTopLevelDeps: true,
          strictOutOfSync: shouldBeStrictForManifestAndLockfileOutOfSync,
        },
      );
    case NodeLockfileVersion.NpmLockV2:
    case NodeLockfileVersion.NpmLockV3:
      return await lockFileParser.parseNpmLockV2Project(
        manifestFileContents,
        lockFileContents,
        {
          includeDevDeps: shouldIncludeDevDependencies,
          includeOptionalDeps: true,
          pruneCycles: true,
          strictOutOfSync: shouldBeStrictForManifestAndLockfileOutOfSync,
        },
      );
  }
  throw new Error(
    "Failed to build dep graph from current project, unknown lockfile version : " +
      lockfileVersion.toString() +
      ".",
  );
}

async function buildDepGraphFromDepTree(
  manifestFileContents: string,
  lockFileContents: string,
  lockfileType: LockfileType,
  shouldIncludeDevDependencies: boolean,
  shouldBeStrictForManifestAndLockfileOutOfSync: boolean,
) {
  const parserResult = await lockFileParser.buildDepTree(
    manifestFileContents,
    lockFileContents,
    shouldIncludeDevDependencies,
    lockfileType,
    shouldBeStrictForManifestAndLockfileOutOfSync,
    // Don't provide a default manifest file name, prefer the parser to infer it.
  );
  const strippedLabelsParserResult = stripUndefinedLabels(parserResult);
  return await legacy.depTreeToGraph(strippedLabelsParserResult, lockfileType);
}

export function getLockFileVersion(
  lockFilePath: string,
  lockFileContents: string,
): NodeLockfileVersion {
  let lockfileVersion: NodeLockfileVersion;

  if (lockFilePath.endsWith("package-lock.json")) {
    lockfileVersion = getNpmLockfileVersion(lockFileContents);
  } else if (lockFilePath.endsWith("yarn.lock")) {
    lockfileVersion = getYarnLockfileVersion(lockFileContents);
  } else if (lockFilePath.endsWith("pnpm-lock.yaml")) {
    lockfileVersion = getPnpmLockfileVersion(lockFileContents);
  } else {
    throw new InvalidUserInputError(
      `Unknown lockfile ${lockFilePath}. ` +
        "Please provide either package-lock.json, yarn.lock or pnpm-lock.yaml",
    );
  }

  return lockfileVersion;
}

export function shouldBuildDepTree(lockfileVersion: NodeLockfileVersion) {
  return !(
    lockfileVersion === NodeLockfileVersion.YarnLockV1 ||
    lockfileVersion === NodeLockfileVersion.YarnLockV2 ||
    lockfileVersion === NodeLockfileVersion.NpmLockV2 ||
    lockfileVersion === NodeLockfileVersion.NpmLockV3
  );
}
