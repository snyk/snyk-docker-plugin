import * as path from "path";
import { parsePkgJson } from "snyk-nodejs-lockfile-parser";
import { ApplicationFilesFact } from "../../facts";
import {
  manifestLockName as nodeManifestLockName,
  manifestName as nodeManifestName,
} from "./node-modules-utils";
import {
  AppDepsScanResultWithoutTarget,
  AppFileType,
  ApplicationFileInfo,
  FilePathToContent,
  ManifestMetadata,
} from "./types";

interface AppFileMetadataExtractor {
  manifestFileMatcher: (filePath: string) => boolean;
  metadataExtractor: (fileContent: string) => ManifestMetadata | undefined;
}

export const filesMetadataExtractorPerLanguage: Record<
  string,
  AppFileMetadataExtractor
> = {
  node: {
    manifestFileMatcher: (filePath: string) => {
      return [nodeManifestName, nodeManifestLockName].some(
        (mf) => path.basename(filePath) === mf,
      );
    },
    metadataExtractor: (fileContent: string) => {
      try {
        const pkgJson = parsePkgJson(fileContent);
        const moduleName = pkgJson.name;
        const repoUrl = (pkgJson as any).repository?.url;

        if (!repoUrl && !moduleName) {
          return undefined;
        }
        const metadata: ManifestMetadata = {
          moduleName: pkgJson.name,
        };
        if (repoUrl) {
          metadata.repoUrl = repoUrl;
        }
        return metadata;
      } catch (err) {
        return undefined;
      }
    },
  },
};

export function getAppFileInfos(
  filePathToContent: FilePathToContent,
  rootDir: string,
  manifestMetadataExtractor?: AppFileMetadataExtractor,
): ApplicationFileInfo[] {
  const appFiles: ApplicationFileInfo[] = [];

  const filePaths = Object.keys(filePathToContent);
  if (!filePaths.length) {
    return appFiles;
  }

  for (const filePath of filePaths) {
    const appFile: ApplicationFileInfo = { path: filePath };
    if (manifestMetadataExtractor) {
      const { manifestFileMatcher, metadataExtractor } =
        manifestMetadataExtractor;
      if (manifestFileMatcher(filePath)) {
        appFile.type = AppFileType.Manifest;
        const manifestContent = filePathToContent[filePath];
        appFile.metadata = metadataExtractor(manifestContent);
      }
    }

    appFiles.push(appFile);
  }

  // Remove the common path prefix from each appFile
  appFiles.forEach((file) => {
    const prefix = rootDir.endsWith(path.sep)
      ? rootDir
      : `${rootDir}${path.sep}`;
    if (file.path.startsWith(prefix)) {
      file.path = file.path.substring(prefix.length); // Remove rootDir from path
    }
  });

  return appFiles;
}

export function getRootDir(filePaths: string[]): string {
  if (!filePaths.length) {
    return path.sep;
  }

  const splitPaths: string[][] = [];
  for (const filePath of filePaths) {
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
  return rootDir || path.sep;
}

export function getApplicationFiles(
  filePathToContent: FilePathToContent,
  language: string,
  identityType: string,
): AppDepsScanResultWithoutTarget[] {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const manifestMetadataExtractor = filesMetadataExtractorPerLanguage[language];
  const appFilesRootDir = getRootDir(Object.keys(filePathToContent));
  const appFiles = getAppFileInfos(
    filePathToContent,
    appFilesRootDir,
    manifestMetadataExtractor,
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
