import * as scanSchemas from "@snyk/scan-schemas";
import * as path from "path";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";

interface FilePathToContent {
  [filePath: string]: string;
}

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
  lockType: lockFileParser.LockfileType;
}

export async function nodeLockFilesToData(
  filePathToContent: FilePathToContent,
): Promise<scanSchemas.deptree.DepTreeScanResult[]> {
  const scanResults: scanSchemas.deptree.DepTreeScanResult[] = [];

  const filePairs = findManifestLockPairsInSameDirectory(filePathToContent);
  // TODO name "thing"
  for (const thing of filePairs) {
    // TODO: consider spinning the event loop
    // TODO: initially generate as DepGraph
    const parserResult = await lockFileParser.buildDepTree(
      filePathToContent[thing.manifest],
      filePathToContent[thing.lock],
      false, // TODO: dev dependencies? can grab from options probably? seems to be ignored though?
      thing.lockType,
      false, // TODO: options.strictOutOfSync !== false; ?
      undefined, // TODO: default manifest file name?
    );

    // TODO: handling a mismatch between what the CLI wants
    // https://github.com/snyk/snyk-cli-interface/blob/master/legacy/common.ts#L16
    // and what the NodeJS parser returns ()
    // https://github.com/snyk/nodejs-lockfile-parser/blob/master/lib/parsers/index.ts#L45
    // because of the labels of DepTreeDep
    // seems to be disregarded here?
    // https://github.com/snyk/snyk/blob/master/src/lib/plugins/nodejs-plugin/index.ts#L20
    const optionalLabels = parserResult.labels;
    const mandatoryLabels: { [key: string]: string } = {};
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

    scanResults.push({
      scanType: "DepTreeScanResult",
      schemaVersion: scanSchemas.deptree.SCHEMA_VERSION,
      depTree: parserResultWithProperLabels,
      plugin: {
        // TODO this should be punishable
        name: "egg-plugin-name",
        runtime: undefined,
        packageManager: undefined,
        dockerImageId: "egg-docker-image-id",
        imageLayers: [],
      },
      packageManager: thing.lockType,
    });
  }

  return scanResults;
}

function findManifestLockPairsInSameDirectory(
  filePathToContent: FilePathToContent,
): ManifestLockPathPair[] {
  const directoryToFiles = groupFilesByDirectory(filePathToContent);
  const manifestLockPathPairs: ManifestLockPathPair[] = [];

  for (const directoryPath of Object.keys(directoryToFiles)) {
    const filesInDirectory = directoryToFiles[directoryPath];
    if (filesInDirectory.length !== 2) {
      // either a missing file or too many files, ignore
      continue;
    }
    if (
      filesInDirectory.includes("package.json") &&
      filesInDirectory.includes("package-lock.json")
    ) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "package.json"),
        lock: path.join(directoryPath, "package-lock.json"),
        lockType: lockFileParser.LockfileType.npm,
      });
      continue;
    }
    if (
      filesInDirectory.includes("package.json") &&
      filesInDirectory.includes("yarn.lock")
    ) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "package.json"),
        lock: path.join(directoryPath, "yarn.lock"),
        lockType: lockFileParser.LockfileType.yarn,
      });
      continue;
    }
    // implicitly ignored case: a directory with package-lock.json and yarn.lock
  }

  return manifestLockPathPairs;
}

// assumption: we only care about manifest+lock files if they are in the same directory
function groupFilesByDirectory(
  filePathToContent: FilePathToContent,
): { [directoryName: string]: string[] } {
  const directoryToFiles: { [directoryName: string]: string[] } = {};
  for (const filePath of Object.keys(filePathToContent)) {
    const directory = path.dirname(filePath);
    const fileName = path.basename(filePath);
    if (!directoryToFiles[directory]) {
      directoryToFiles[directory] = [];
    }
    directoryToFiles[directory].push(fileName);
  }
  return directoryToFiles;
}
