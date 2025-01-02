import * as path from "path";
import { ApplicationFilesFact } from "../../facts";
import {
  AppDepsScanResultWithoutTarget,
  ApplicationFileInfo,
  FilePathToContent,
} from "./types";

export function getAppFilesRootDir(
  filePaths: string[],
): [string, ApplicationFileInfo[]] {
  const appFiles: ApplicationFileInfo[] = [];
  const splitPaths: string[][] = [];

  if (!filePaths.length) {
    return [path.sep, appFiles];
  }

  for (const filePath of filePaths) {
    appFiles.push({ path: filePath });
    splitPaths.push(filePath.split("/").filter(Boolean));
  }

  // Find the shortest path length to prevent out-of-bounds access
  const minLength = Math.min(...splitPaths.map((path) => path.length));

  // Find the common parts of the paths
  const commonParts: string[] = [];
  for (let i = 0; i < minLength - 1; i++) {
    const currentPart = splitPaths[0][i];
    if (splitPaths.every((path) => path[i] === currentPart)) {
      commonParts.push(currentPart);
    } else {
      break;
    }
  }

  // Join the common parts to form the common directory
  const rootDir = "/" + commonParts.join("/");

  // Remove the common path prefix from each appFile
  appFiles.forEach((file) => {
    const prefix = rootDir === path.sep ? rootDir : `${rootDir}${path.sep}`;
    if (file.path.startsWith(prefix)) {
      file.path = file.path.substring(prefix.length); // Remove rootDir from path
    }
  });

  return [rootDir || path.sep, appFiles];
}

export function getApplicationFiles(
  filePathToContent: FilePathToContent,
  language: string,
  identityType: string,
): AppDepsScanResultWithoutTarget[] {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const [appFilesRootDir, appFiles] = getAppFilesRootDir(
    Object.keys(filePathToContent),
  );
  if (appFiles.length) {
    scanResults.push({
      facts: [
        {
          type: "applicationFiles",
          data: [
            {
              language,
              fileHierarchy: appFiles,
            },
          ],
        } as ApplicationFilesFact,
      ],
      identity: {
        type: identityType,
        targetFile: appFilesRootDir,
      },
    });
  }

  return scanResults;
}
