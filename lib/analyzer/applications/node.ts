import { legacy } from "@snyk/dep-graph";
import * as Debug from "debug";
import * as path from "path";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import * as resolveDeps from "snyk-resolve-deps";
import { DepGraphFact, TestedFilesFact } from "../../facts";

const debug = Debug("snyk");

import { PkgTree } from "snyk-nodejs-lockfile-parser";
import { LogicalRoot } from "snyk-resolve-deps/dist/types";
import {
  cleanupAppNodeModules,
  groupFilesByDirectory,
  filterAppFiles,
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

  const filePaths = Object.keys(filePathToContent);
  if (filePaths.length === 0) {
    return [];
  }

  const fileNamesGroupedByDirectory = groupFilesByDirectory(filePaths);
  const [appFilesRootDir, appFiles] = filterAppFiles(
    fileNamesGroupedByDirectory,
  );
  const [manifestFilePairs, nodeProjects] = findProjectsAndManifests(
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
  if (nodeProjects.length !== 0) {
    scanResults.push(
      ...(await depGraphFromNodeModules(
        filePathToContent,
        nodeProjects,
        fileNamesGroupedByDirectory,
      )),
    );
  }
  if (appFiles.length !== 0) {
    scanResults.push({
      facts: [
        {
          type: "applicationFiles",
          data: appFiles,
        },
      ],
      identity: {
        type: "npm",
        targetFile: appFilesRootDir,
      },
    });
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
        await cleanupAppNodeModules(tempDir);
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
    // TODO: initially generate as DepGraph
    let parserResult: PkgTree;
    try {
      parserResult = await lockFileParser.buildDepTree(
        filePathToContent[pathPair.manifest],
        filePathToContent[pathPair.lock],
        shouldIncludeDevDependencies,
        pathPair.lockType,
        shouldBeStrictForManifestAndLockfileOutOfSync,
        // Don't provide a default manifest file name, prefer the parser to infer it.
      );
    } catch (err) {
      debug(
        `An error occurred while analysing a pair of manifest and lock files: ${err.message}`,
      );
      continue;
    }

    const strippedLabelsParserResult = stripUndefinedLabels(parserResult);
    const depGraph = await legacy.depTreeToGraph(
      strippedLabelsParserResult,
      pathPair.lockType,
    );

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

function findProjectsAndManifests(
  fileNamesGroupedByDirectory: FilesByDirMap,
): [ManifestLockPathPair[], string[]] {
  const manifestLockPathPairs: ManifestLockPathPair[] = [];
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
      continue;
    }
    nodeProjects.push(directoryPath);
  }

  return [manifestLockPathPairs, nodeProjects];
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
