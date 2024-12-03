import * as path from "path";
import { ApplicationFileInfo } from "./types";

export function filterAppFiles(
  filePaths: string[],
  languageFileValidator: (filePath: string) => boolean,
): [string, ApplicationFileInfo[]] {
  const appFiles: ApplicationFileInfo[] = [];
  let rootDir: string = "";
  const directories: Set<string> = new Set();

  for (const filePath of filePaths) {
    if (languageFileValidator(filePath)) {
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
