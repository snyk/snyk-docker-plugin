import * as path from "path";

export function filterAppFiles(filePaths: string[]): [string, string[]] {
  const appFiles: string[] = [];
  let rootDir: string = "."; // Default to "." if no common root directory is found
  const directories: Set<string> = new Set();

  for (const filePath of filePaths) {
    if (
      !filePath.includes("site-packages/") &&
      !filePath.includes("dist-packages/") &&
      filePath.endsWith(".py")
    ) {
      appFiles.push(filePath);
      directories.add(path.dirname(filePath)); // Collect directories of app files
    }
  }

  // Determine the common directory
  if (appFiles.length > 0) {
    rootDir = Array.from(directories).reduce((commonDir, dir) => {
      // Find the common path
      while (commonDir && commonDir !== "." && !dir.startsWith(commonDir)) {
        commonDir = commonDir.substring(0, commonDir.lastIndexOf(path.sep));
      }
      return commonDir;
    }, directories.values().next().value);
  }

  return [rootDir, appFiles];
}
