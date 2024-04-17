import { legacy } from "@snyk/dep-graph";
import * as Debug from "debug";
import * as path from "path";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import * as resolveDeps from "snyk-resolve-deps";
import { DepGraphFact, TestedFilesFact } from "../../facts";

const debug = Debug("snyk");

import {
  cleanupAppNodeModules,
  groupFilesByDirectory,
  persistAppNodeModules,
} from "./node-modules-utils";
import {
  AppDepsScanResultWithoutTarget,
  FilePathToContent,
  FilesByDir,
} from "./types";

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
  lockType: lockFileParser.LockfileType;
}

export async function nodeFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
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

  const fileNamesGroupedByDirectory = groupFilesByDirectory(filePathToContent);
  const manifestFilePairs = findManifestLockPairsInSameDirectory(
    fileNamesGroupedByDirectory,
  );

  return manifestFilePairs.length === 0
    ? depGraphFromNodeModules(filePathToContent, fileNamesGroupedByDirectory)
    : depGraphFromManifestFiles(filePathToContent, manifestFilePairs);
}

async function depGraphFromNodeModules(
  filePathToContent: FilePathToContent,
  fileNamesGroupedByDirectory: FilesByDir,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const { tempDir, tempApplicationPath, manifestPath } =
    await persistAppNodeModules(filePathToContent, fileNamesGroupedByDirectory);

  if (!tempApplicationPath) {
    return [];
  }

  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  try {
    const pkgTree: lockFileParser.PkgTree = await resolveDeps(
      tempApplicationPath,
      {
        dev: false,
        noFromArrays: true,
      },
    );

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
          data: Object.keys(filePathToContent),
        },
      ],
      identity: {
        type: depGraph.pkgManager.name,
        targetFile: manifestPath,
      },
    });
  } catch (error) {
    debug(
      `An error occurred while analysing node_modules dir: ${error.message}`,
    );
  } finally {
    await cleanupAppNodeModules(tempDir);
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
    const parserResult = await lockFileParser.buildDepTree(
      filePathToContent[pathPair.manifest],
      filePathToContent[pathPair.lock],
      shouldIncludeDevDependencies,
      pathPair.lockType,
      shouldBeStrictForManifestAndLockfileOutOfSync,
      // Don't provide a default manifest file name, prefer the parser to infer it.
    );

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

function findManifestLockPairsInSameDirectory(
  fileNamesGroupedByDirectory: FilesByDir,
): ManifestLockPathPair[] {
  const manifestLockPathPairs: ManifestLockPathPair[] = [];

  for (const directoryPath of Object.keys(fileNamesGroupedByDirectory)) {
    if (directoryPath.includes("node_modules")) {
      continue;
    }
    const filesInDirectory = fileNamesGroupedByDirectory[directoryPath];
    if (filesInDirectory.length !== 2) {
      // either a missing file or too many files, ignore
      continue;
    }

    const hasPackageJson = filesInDirectory.includes("package.json");
    const hasPackageLockJson = filesInDirectory.includes("package-lock.json");
    const hasYarnLock = filesInDirectory.includes("yarn.lock");

    if (hasPackageJson && hasPackageLockJson) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "package.json"),
        lock: path.join(directoryPath, "package-lock.json"),
        lockType: lockFileParser.LockfileType.npm,
      });
      continue;
    }

    if (hasPackageJson && hasYarnLock) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "package.json"),
        lock: path.join(directoryPath, "yarn.lock"),
        lockType: lockFileParser.LockfileType.yarn,
      });
      continue;
    }
  }

  return manifestLockPathPairs;
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
