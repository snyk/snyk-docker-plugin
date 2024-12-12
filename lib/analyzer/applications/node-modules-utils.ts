import * as Debug from "debug";
import { mkdir, mkdtemp, rm, stat, writeFile } from "fs/promises";
import * as path from "path";
import { FilePathToContent, FilesByDirMap } from "./types";
const debug = Debug("snyk");

const nodeModulesRegex = /^(.*?)(?:[\\\/]node_modules)/;

export {
  persistNodeModules,
  cleanupAppNodeModules,
  groupFilesByDirectory,
  isNodeAppFile,
};

interface ScanPaths {
  tempDir: string;
  tempProjectPath: string;
  manifestPath?: string;
}

async function createTempProjectDir(
  projectDir: string,
): Promise<{ tmpDir: string; tempProjectRoot: string }> {
  const tmpDir = await mkdtemp("snyk");

  const tempProjectRoot = path.join(tmpDir, projectDir);

  await mkdir(tempProjectRoot, { recursive: true });

  return {
    tmpDir,
    tempProjectRoot,
  };
}

const manifestName: string = "package.json";

async function fileExists(path: string): Promise<boolean> {
  return await stat(path)
    .then(() => true)
    .catch(() => false);
}

async function createSyntheticManifest(
  tempRootManifestDir: string,
): Promise<void> {
  const tempRootManifestPath = path.join(tempRootManifestDir, manifestName);
  debug(`Creating an empty synthetic manifest file: ${tempRootManifestPath}`);
  try {
    await writeFile(tempRootManifestPath, "{}", "utf-8");
  } catch (error) {
    debug(
      `Error while writing file ${tempRootManifestPath} : ${error.message}`,
    );
  }
}

async function saveOnDisk(
  tempDir: string,
  modules: Set<string>,
  filePathToContent: FilePathToContent,
): Promise<void> {
  for (const module of modules) {
    const manifestContent = filePathToContent[module];
    if (!manifestContent) {
      continue;
    }
    await createFile(path.join(tempDir, module), manifestContent);
  }
}

async function persistNodeModules(
  project: string,
  filePathToContent: FilePathToContent,
  fileNamesGroupedByDirectory: FilesByDirMap,
): Promise<ScanPaths> {
  const modules = fileNamesGroupedByDirectory.get(project);
  const tmpDir: string = "";
  const tempProjectRoot: string = "";

  if (!modules || modules.size === 0) {
    debug(`Empty application directory tree.`);

    return {
      tempDir: tmpDir,
      tempProjectPath: tempProjectRoot,
    };
  }

  try {
    const { tmpDir, tempProjectRoot } = await createTempProjectDir(project);

    await saveOnDisk(tmpDir, modules, filePathToContent);

    const result: ScanPaths = {
      tempDir: tmpDir,
      tempProjectPath: tempProjectRoot,
      manifestPath: path.join(
        tempProjectRoot.substring(tmpDir.length),
        manifestName,
      ),
    };

    const manifestFileExists = await fileExists(
      path.join(tempProjectRoot, manifestName),
    );

    if (!manifestFileExists) {
      await createSyntheticManifest(tempProjectRoot);
      delete result.manifestPath;
    }
    return result;
  } catch (error) {
    debug(
      `Failed to copy the application manifest files locally: ${error.message}`,
    );
    return {
      tempDir: tmpDir,
      tempProjectPath: tempProjectRoot,
    };
  }
}

async function createFile(filePath, fileContent): Promise<void> {
  try {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, fileContent, "utf-8");
  } catch (error) {
    debug(`Error while creating file ${filePath} : ${error.message}`);
  }
}

function isYarnCacheDependency(filePath: string): boolean {
  if (
    filePath.includes(".yarn/cache") ||
    filePath.includes(".cache/yarn") ||
    filePath.includes("yarn\\cache") ||
    filePath.includes("cache\\yarn") ||
    filePath.includes("Cache\\Yarn") ||
    filePath.includes("Yarn\\Cache")
  ) {
    return true;
  }
  return false;
}

function isNpmCacheDependency(filePath: string): boolean {
  if (filePath.includes(".npm/") || filePath.includes("\\npm-cache")) {
    return true;
  }
  return false;
}

function isPnpmCacheDependency(filePath: string): boolean {
  if (
    filePath.includes("pnpm-store") ||
    filePath.includes("pnpm/store") ||
    filePath.includes("pnpm\\store")
  ) {
    return true;
  }
  return false;
}

function getNodeModulesParentDir(filePath: string): string | null {
  const nodeModulesParentDirMatch = nodeModulesRegex.exec(filePath);

  if (nodeModulesParentDirMatch && nodeModulesParentDirMatch.length > 1) {
    const nodeModulesParentDir = nodeModulesParentDirMatch[1];
    if (nodeModulesParentDir === "") {
      return "/"; // ensuring the same behavior of path.dirname for '/' dir
    }
    return nodeModulesParentDir;
  }
  return null;
}

function getGroupingDir(filePath: string): string {
  const nodeModulesParentDir = getNodeModulesParentDir(filePath);

  if (nodeModulesParentDir) {
    return nodeModulesParentDir;
  }
  return path.dirname(filePath);
}

function groupFilesByDirectory(filePaths: string[]): FilesByDirMap {
  const filesByDir: FilesByDirMap = new Map();

  for (const filePath of filePaths) {
    if (isNpmCacheDependency(filePath)) {
      continue;
    }
    if (isYarnCacheDependency(filePath)) {
      continue;
    }
    if (isPnpmCacheDependency(filePath)) {
      continue;
    }
    const directory = getGroupingDir(filePath);

    if (!filesByDir.has(directory)) {
      filesByDir.set(directory, new Set());
    }
    filesByDir.get(directory)?.add(filePath);
  }
  return filesByDir;
}

function isNodeAppFile(filepath: string): boolean {
  const fileBase = path.basename(filepath);
  return (
    !filepath.includes("node_modules/") &&
    (filepath.endsWith(".js") ||
      (filepath.endsWith(".ts") && !filepath.endsWith(".d.ts")) ||
      fileBase === "package.json" ||
      fileBase === "package-lock.json")
  );
}

async function cleanupAppNodeModules(appRootDir: string): Promise<void> {
  if (!appRootDir) {
    return;
  }

  try {
    await rm(appRootDir, { recursive: true });
  } catch (error) {
    debug(`Error while removing ${appRootDir} : ${error.message}`);
  }
}
