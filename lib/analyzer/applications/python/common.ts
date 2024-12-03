import * as path from "path";
import {
  ApplicationFileInfo,
  AppDepsScanResultWithoutTarget,
  FilePathToContent,
} from "../types";
import { ApplicationFilesFact } from "../../../facts";

export function getPythonApplicationFiles(
  filePathToContent: FilePathToContent,
) {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

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

  return scanResults;
}

export function filterAppFiles(
  filePaths: string[],
): [string, ApplicationFileInfo[]] {
  const appFiles: ApplicationFileInfo[] = [];
  let rootDir: string = "";
  const directories: Set<string> = new Set();

  for (const filePath of filePaths) {
    if (
      !filePath.includes("/site-packages/") &&
      !filePath.includes("/dist-packages/") &&
      // "/usr/" should not include 1st party code
      !filePath.startsWith("/usr/") &&
      filePath.endsWith(".py")
    ) {
      appFiles.push({ path: filePath });
      directories.add(path.dirname(filePath)); // Collect directories of app files
    }
  }

  // Determine the common directory
  if (appFiles.length > 0) {
    rootDir = Array.from(directories).reduce((commonDir, dir) => {
      // Find the common path
      while (commonDir && commonDir !== "" && !dir.startsWith(commonDir)) {
        commonDir = commonDir.substring(0, commonDir.lastIndexOf(path.sep));
      }
      return commonDir;
    }, directories.values().next().value);
  }

  // Remove the common path prefix from each appFile
  appFiles.forEach((file) => {
    file.path = file.path.replace(`${rootDir}${path.sep}`, ""); // Remove rootDir from path
  });

  return [rootDir, appFiles];
}
