import { filterAppFiles } from "../../../../lib/analyzer/applications/common";
import { ApplicationFilesFact } from "../../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";

export function getPythonApplicationFiles(
  filePathToContent: FilePathToContent,
) {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const [appFilesRootDir, appFiles] = filterAppFiles(
    Object.keys(filePathToContent),
    isPythonAppFile,
  );

  if (appFiles.length) {
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

export function isPythonAppFile(filepath: string): boolean {
  return (
    !filepath.includes("/site-packages/") &&
    !filepath.includes("/dist-packages/") &&
    // "/usr/" should not include 1st party code
    !filepath.startsWith("/usr/") &&
    filepath.endsWith(".py")
  );
}
