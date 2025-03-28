import { legacy } from "@snyk/dep-graph";
import * as path from "path";
import { DepGraphFact, TestedFilesFact } from "../../facts";

import {
  buildDepTree,
  ComposerParserResponse,
} from "@snyk/composer-lockfile-parser";
import { InvalidUserInputError } from "@snyk/composer-lockfile-parser/dist/errors";
import { DepTreeDep } from "../../types";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
}
const PACKAGE_MANAGER_TYPE = "composer";

export async function phpFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const filePairs = findManifestLockPairsInSameDirectory(filePathToContent);

  const shouldIncludeDevDependencies = false;

  for (const pathPair of filePairs) {
    let parserResult: ComposerParserResponse | undefined;
    try {
      parserResult = buildDepTree(
        filePathToContent[pathPair.lock],
        filePathToContent[pathPair.manifest],
        pathPair.manifest,
        {},
        shouldIncludeDevDependencies,
      );
    } catch (e) {
      // This will skip parsing all files that error due to being malformed.
      // If we do not do this, the entire scan will fail.
      // Ideally, we'd like to log this, but logging does not exist in this library.
      if (e instanceof InvalidUserInputError) {
        continue;
      } else {
        throw e;
      }
    }

    const depGraph = await legacy.depTreeToGraph(
      parserResult as DepTreeDep,
      PACKAGE_MANAGER_TYPE,
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
        targetFile: pathPair.lock,
      },
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

    const hasComposerJson = filesInDirectory.includes("composer.json");
    const hasComposerLock = filesInDirectory.includes("composer.lock");

    if (hasComposerJson && hasComposerLock) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "composer.json"),
        lock: path.join(directoryPath, "composer.lock"),
      });
    }
  }

  return manifestLockPathPairs;
}

// assumption: we only care about manifest+lock files if they are in the same directory
function groupFilesByDirectory(filePathToContent: FilePathToContent): {
  [directoryName: string]: string[];
} {
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
