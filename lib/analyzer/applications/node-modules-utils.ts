import * as Debug from "debug";
import { mkdir, mkdtemp, rm, stat, writeFile } from "fs/promises";
import * as path from "path";

import { FilePathToContent, FilesByDir } from "./types";
const debug = Debug("snyk");

export { persistAppNodeModules, cleanupAppNodeModules, groupFilesByDirectory };

interface ScanPaths {
  tempDir: string;
  tempApplicationPath: string;
  manifestPath?: string;
}

async function createTempAppDir(appParentDir: string): Promise<string[]> {
  const tmpDir = await mkdtemp("snyk");

  const appRootDir = appParentDir.includes("node_modules")
    ? appParentDir.substring(0, appParentDir.indexOf("node_modules"))
    : appParentDir;

  const tempAppRootDirPath = path.join(tmpDir, appRootDir);

  await mkdir(tempAppRootDirPath, { recursive: true });

  return [tmpDir, tempAppRootDirPath];
}

const manifestName: string = "package.json";

async function fileExists(path: string): Promise<boolean> {
  return await stat(path)
    .then(() => true)
    .catch(() => false);
}

async function createAppSyntheticManifest(
  tempRootManifestDir: string,
): Promise<void> {
  const tempRootManifestPath = path.join(tempRootManifestDir, manifestName);
  debug(`Creating an empty synthetic manifest file: ${tempRootManifestPath}`);
  await writeFile(tempRootManifestPath, "{}", "utf-8");
}

async function copyAppModulesManifestFiles(
  appDirs: string[],
  tempAppRootDirPath: string,
  fileNamesGroupedByDirectory: FilesByDir,
  filePathToContent: FilePathToContent,
) {
  for (const dependencyPath of appDirs) {
    const filesInDirectory = fileNamesGroupedByDirectory[dependencyPath];
    if (filesInDirectory.length === 0) {
      continue;
    }

    const manifestPath = path.join(dependencyPath, "package.json");
    const manifestContent = filePathToContent[manifestPath];

    await createFile(
      path.join(tempAppRootDirPath, manifestPath),
      manifestContent,
    );
  }
}

async function persistAppNodeModules(
  filePathToContent: FilePathToContent,
  fileNamesGroupedByDirectory: FilesByDir,
): Promise<ScanPaths> {
  const appDirs = Object.keys(fileNamesGroupedByDirectory);
  let tmpDir: string = "";
  let tempAppRootDirPath: string = "";

  if (appDirs.length === 0) {
    debug(`Empty application directory tree.`);

    return {
      tempDir: tmpDir,
      tempApplicationPath: tempAppRootDirPath,
    };
  }

  try {
    [tmpDir, tempAppRootDirPath] = await createTempAppDir(appDirs.sort()[0]);

    await copyAppModulesManifestFiles(
      appDirs,
      tmpDir,
      fileNamesGroupedByDirectory,
      filePathToContent,
    );

    const result: ScanPaths = {
      tempDir: tmpDir,
      tempApplicationPath: tempAppRootDirPath,
      manifestPath: path.join(
        tempAppRootDirPath.substring(tmpDir.length),
        manifestName,
      ),
    };

    const manifestFileExists = await fileExists(
      path.join(tempAppRootDirPath, manifestName),
    );

    if (!manifestFileExists) {
      await createAppSyntheticManifest(tempAppRootDirPath);
      delete result.manifestPath;
    }
    return result;
  } catch (error) {
    debug(
      `Failed to copy the application manifest files locally: ${error.message}`,
    );
    return {
      tempDir: tmpDir,
      tempApplicationPath: tempAppRootDirPath,
    };
  }
}

async function createFile(filePath, fileContent) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, fileContent, "utf-8");
}

function groupFilesByDirectory(
  filePathToContent: FilePathToContent,
): FilesByDir {
  const fileNamesGrouped: FilesByDir = {};
  for (const filePath of Object.keys(filePathToContent)) {
    const directory = path.dirname(filePath);
    const fileName = path.basename(filePath);
    if (!fileNamesGrouped[directory]) {
      fileNamesGrouped[directory] = [];
    }
    fileNamesGrouped[directory].push(fileName);
  }
  return fileNamesGrouped;
}

async function cleanupAppNodeModules(appRootDir: string) {
  try {
    rm(appRootDir, { recursive: true });
  } catch (error) {
    debug(`Error while removing ${appRootDir} : ${error.message}`);
  }
}
