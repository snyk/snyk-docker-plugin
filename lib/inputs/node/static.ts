import * as Debug from "debug";
import { basename } from "path";
import { getApplicationFiles } from "../../analyzer/applications/runtime-common";
import {
  AppDepsScanResultWithoutTarget,
  FilePathToContent,
} from "../../analyzer/applications/types";
import { ExtractAction } from "../../extractor/types";
import { ApplicationFilesFact } from "../../facts";
import { streamToString } from "../../stream-utils";

const debug = Debug("snyk");
const nodeAppFiles = ["package.json", "package-lock.json", "yarn.lock"];
const deletedAppFiles = nodeAppFiles.map((file) => ".wh." + file);

const jsExtension = ".js";
const jsMapExtension = ".js.map";

const nodeJsTsAppFileSuffixes = [
  jsExtension,
  jsMapExtension,
  ".ts",
  "package.json",
  "package-lock.json",
];
const excludedNodeJsTsAppFileSuffixes = [".d.ts"];

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return nodeAppFiles.includes(fileName) || deletedAppFiles.includes(fileName);
}

export const getNodeAppFileContentAction: ExtractAction = {
  actionName: "node-app-files",
  filePathMatches,
  callback: streamToString,
};

function nodeJsTsAppFilePathMatches(filePath: string): boolean {
  return (
    !filePath.includes("node_modules/") &&
    // "/usr/" should not include 1st party code
    !filePath.startsWith("/usr/") &&
    nodeJsTsAppFileSuffixes.some((suffix) => filePath.endsWith(suffix)) &&
    !excludedNodeJsTsAppFileSuffixes.some((excludedSuffix) =>
      filePath.endsWith(excludedSuffix),
    )
  );
}

export const getNodeJsTsAppFileContentAction: ExtractAction = {
  actionName: "node-js-ts-app-files",
  filePathMatches: nodeJsTsAppFilePathMatches,
  callback: streamToString,
};

function getMinimizedJsMapFileIfExists(
  nodeAppFiles: string[],
): string | undefined {
  const jsMapFiles = nodeAppFiles.filter((file) =>
    file.endsWith(jsMapExtension),
  );
  const jsFiles = nodeAppFiles.filter((file) => file.endsWith(jsExtension));

  if (jsMapFiles.length !== 1 || jsFiles.length !== 1) {
    // In case of webpack / esbuild minimization we expect a single js and js.map file
    return undefined;
  }

  const jsMapFile = jsMapFiles[0];
  const matchingJsFile = jsMapFile.substring(0, jsMapFile.length - 4); // Remove .map suffix
  return nodeAppFiles.includes(matchingJsFile) ? jsMapFile : undefined;
}

function getNodeJsMinimizedAppFiles(
  nodeAppFilesContents: FilePathToContent,
  jsMapFile: string,
): AppDepsScanResultWithoutTarget | undefined {
  const jsMapContent = nodeAppFilesContents[jsMapFile];
  try {
    const parsedJsMap = JSON.parse(jsMapContent);
    if (Array.isArray(parsedJsMap.sources)) {
      const fileHierarchy = parsedJsMap.sources.map((t: string) => {
        return { path: t };
      });
      return {
        facts: [
          {
            type: "applicationFiles",
            data: [
              {
                language: "node",
                fileHierarchy,
                minimized: true,
              },
            ],
          } as ApplicationFilesFact,
        ],
        identity: {
          type: "npm",
          targetFile: jsMapFile,
        },
      };
    }
  } catch (err) {
    debug(`Failed parsing js.map file: ${jsMapFile}`, err);
  }

  return undefined;
}

export function getNodeApplicationFilesScanResults(
  nodeAppFilesContents: FilePathToContent,
): AppDepsScanResultWithoutTarget[] {
  const result = getApplicationFiles(nodeAppFilesContents, "node", "npm");
  const nodeAppFiles = Object.keys(nodeAppFilesContents);
  const minimizedJsFile = getMinimizedJsMapFileIfExists(nodeAppFiles);
  if (minimizedJsFile) {
    const minimizedAppFiles = getNodeJsMinimizedAppFiles(
      nodeAppFilesContents,
      minimizedJsFile,
    );
    if (minimizedAppFiles) {
      result.push(minimizedAppFiles);
    }
  }

  return result;
}
