import * as path from "path";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";

import { ScannedProjectCustom } from "../../types";
import { FilePathToContent } from "./types";

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
  lockType: lockFileParser.LockfileType;
}

export async function nodeFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<ScannedProjectCustom[]> {
  const scanResults: ScannedProjectCustom[] = [];

  const filePairs = findManifestLockPairsInSameDirectory(filePathToContent);

  const shouldIncludeDevDependencies = false;
  const shouldBeStrictForManifestAndLockfileOutOfSync = false;

  for (const pathPair of filePairs) {
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

    scanResults.push({
      depTree: strippedLabelsParserResult,
      packageManager: pathPair.lockType,
      // The targetFile ensures project uniqueness; we choose the manifest file as a target.
      targetFile: pathPair.manifest,
    });
  }

  return scanResults;
}

function findManifestLockPairsInSameDirectory(
  filePathToContent: FilePathToContent,
): ManifestLockPathPair[] {
  const fileNamesGroupedByDirectory = groupFilesByDirectory(filePathToContent);
  const manifestLockPathPairs: ManifestLockPathPair[] = [];

  for (const directoryPath of Object.keys(fileNamesGroupedByDirectory)) {
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

// assumption: we only care about manifest+lock files if they are in the same directory
function groupFilesByDirectory(
  filePathToContent: FilePathToContent,
): { [directoryName: string]: string[] } {
  const fileNamesGroupedByDirectory: { [directoryName: string]: string[] } = {};
  for (const filePath of Object.keys(filePathToContent)) {
    const directory = path.dirname(filePath);
    const fileName = path.basename(filePath);
    if (!fileNamesGroupedByDirectory[directory]) {
      fileNamesGroupedByDirectory[directory] = [];
    }
    fileNamesGroupedByDirectory[directory].push(fileName);
  }
  return fileNamesGroupedByDirectory;
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
