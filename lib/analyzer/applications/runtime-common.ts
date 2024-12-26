import * as Debug from "debug";
import * as path from "path";
import { ApplicationFilesFact } from "../../facts";
import {
  AppDepsScanResultWithoutTarget,
  ApplicationFileInfo,
  FilePathToContent,
} from "./types";

const debug = Debug("snyk");

export function getAppFilesRootDir(
  filePaths: string[],
): [string, ApplicationFileInfo[]] {
  const appFiles: ApplicationFileInfo[] = [];
  let rootDir: string = "";
  const directories: Set<string> = new Set();

  for (const filePath of filePaths) {
    appFiles.push({ path: filePath });
    directories.add(path.dirname(filePath)); // Collect directories of app files
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
    const prefix = `${rootDir}${path.sep}`;
    if (file.path.startsWith(prefix)) {
      file.path = file.path.substring(prefix.length); // Remove rootDir from path
    }
  });

  return [rootDir, appFiles];
}

function collectNodeModuleNames(
  filePathToContent: FilePathToContent,
  appFilesRootDir: string,
  appFiles: ApplicationFileInfo[],
) {
  appFiles.forEach((file) => {
    if (path.basename(file.path) === "package.json") {
      const fullPath = path.join(appFilesRootDir, file.path);
      try {
        const content = filePathToContent[fullPath];
        const parsed = JSON.parse(content);
        if (parsed.name) {
          file.moduleName = parsed.name;
        }
      } catch (error) {
        debug(`Unable to extract node.js module name: ${fullPath}`);
      }
    }
  });
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

  if (language === "node") {
    collectNodeModuleNames(filePathToContent, appFilesRootDir, appFiles);
  }

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
