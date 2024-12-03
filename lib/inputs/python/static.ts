import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const poetryManifestFiles = ["pyproject.toml", "poetry.lock"];
const pipManifestFiles = ["requirements.txt"];
const pythonMetadataFilesRegex =
  /\/lib\/python.*?\/(?:dist|site)-packages\/.*?\.dist-info\/METADATA/;
const deletedPoetryAppFiles = poetryManifestFiles.map((file) => ".wh." + file);
const deletedPipAppFiles = pipManifestFiles.map((file) => ".wh." + file);
const pythonApplicationFileSuffix = ".py";

function poetryFilePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return (
    poetryManifestFiles.includes(fileName) ||
    deletedPoetryAppFiles.includes(fileName)
  );
}

export const getPoetryAppFileContentAction: ExtractAction = {
  actionName: "poetry-app-files",
  filePathMatches: poetryFilePathMatches,
  callback: streamToString,
};

function pipFilePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return (
    pipManifestFiles.includes(fileName) ||
    pythonMetadataFilesRegex.test(filePath) ||
    deletedPipAppFiles.includes(fileName)
  );
}

export const getPipAppFileContentAction: ExtractAction = {
  actionName: "pip-app-files",
  filePathMatches: pipFilePathMatches,
  callback: streamToString,
};

function pythonApplicationFilePathMatches(filePath: string): boolean {
  return filePath.endsWith(pythonApplicationFileSuffix);
}

export const getPythonAppFileContentAction: ExtractAction = {
  actionName: "python-app-files",
  filePathMatches: pythonApplicationFilePathMatches,
  callback: streamToString,
};
