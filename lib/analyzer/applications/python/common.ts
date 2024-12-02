import * as path from "path";
import { ApplicationFileInfo } from "../types";

export function filterAppFiles(
  filePaths: string[],
): [string, ApplicationFileInfo[]] {
  const appFiles: ApplicationFileInfo[] = [];
  let rootDir: string = "";
  const directories: Set<string> = new Set();

  for (const filePath of filePaths) {
    if (
      !filePath.includes("site-packages/") &&
      !filePath.includes("dist-packages/") &&
      // installed eternal packages are installed in `usr/` dir and should not be collected as app files
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

  return [rootDir, appFiles];
}
