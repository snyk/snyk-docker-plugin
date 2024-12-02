import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import * as lockFileParser from "snyk-poetry-lockfile-parser";
import {
  ApplicationFilesFact,
  DepGraphFact,
  TestedFilesFact,
} from "../../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";
import { filterAppFiles } from "./common";

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
}

export async function poetryFilesToScannedProjects(
  filePathToContent: FilePathToContent,
  collectApplicationFiles: boolean,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const filePairs = findManifestLockPairsInSameDirectory(filePathToContent);

  const shouldIncludeDevDependencies = false;

  for (const pathPair of filePairs) {
    const depGraph = await lockFileParser.buildDepGraph(
      filePathToContent[pathPair.manifest],
      filePathToContent[pathPair.lock],
      shouldIncludeDevDependencies,
    );
    if (!depGraph) {
      continue;
    }

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph as DepGraph,
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

  // if no filePairs are available the project is not a poetry and the app files should not be collected here
  if (collectApplicationFiles && filePairs.length) {
    const [appFilesRootDir, appFiles] = filterAppFiles(
      Object.keys(filePathToContent),
    );
    if (appFiles.length !== 0) {
      scanResults.push({
        facts: [
          {
            type: "applicationFiles",
            data: [
              {
                language: "python",
                fileHierarchy: appFiles,
              },
            ],
          } as ApplicationFilesFact,
        ],
        identity: {
          type: "python",
          targetFile: appFilesRootDir,
        },
      });
    }
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
    if (filesInDirectory.length < 2) {
      // either a missing file or too many files, ignore
      continue;
    }

    const hasManifest = filesInDirectory.includes("pyproject.toml");
    const hasLockFile = filesInDirectory.includes("poetry.lock");

    if (hasManifest && hasLockFile) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "pyproject.toml"),
        lock: path.join(directoryPath, "poetry.lock"),
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
