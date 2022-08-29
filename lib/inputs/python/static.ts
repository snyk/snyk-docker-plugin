import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const poetryManifestFiles = ["pyproject.toml", "poetry.lock"];
const pipManifestFiles = ["requirements.txt"];
const pythonMetadataFilesRegex = /\/lib\/python.*?\/site-packages\/.*?\.dist-info\/METADATA/;

function poetryFilePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return poetryManifestFiles.includes(fileName);
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
    pythonMetadataFilesRegex.test(filePath)
  );
}

export const getPipAppFileContentAction: ExtractAction = {
  actionName: "pip-app-files",
  filePathMatches: pipFilePathMatches,
  callback: streamToString,
};
