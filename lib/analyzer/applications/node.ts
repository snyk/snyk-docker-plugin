import * as path from "path";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import * as scanSchemas from "@snyk/scan-schemas";

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
  for (const thing of filePairs) {
    // TODO: consider spinning the event loop
    const parserResult = await lockFileParser.buildDepTree(
      filePathToContent[thing.manifest],
      filePathToContent[thing.lock],
      false, // TODO: dev dependencies? can grab from options probably? seems to be ignored though?
      thing.lockType,
      false, // TODO: options.strictOutOfSync !== false; ?
      undefined, // TODO: default manifest file name?
    );
    
    scanResults.push({
      type: scanSchemas.deptree.TYPE,
      schemaVersion: scanSchemas.deptree.SCHEMA_VERSION,
      data: parserResult,
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
