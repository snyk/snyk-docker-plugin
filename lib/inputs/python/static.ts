import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const poetryFilePatterns = [/^pyproject\.toml$/, /^poetry\.lock$/, /\.py$/];
const pipFilePatterns = [/^requirements\.txt$/, /\.py$/];
const pythonMetadataFilesRegex =
  /\/lib\/python.*?\/(?:dist|site)-packages\/.*?\.dist-info\/METADATA/;
const deletedPoetryAppFilesPatterns = [".wh.pyproject.toml", ".wh.poetry.lock"];
const deletedPipAppFilesPatterns = [".wh.requirements.txt"];

function poetryFilePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return (
    poetryFilePatterns.some((pattern) => new RegExp(pattern).test(fileName)) ||
    deletedPoetryAppFilesPatterns.some((pattern) =>
      new RegExp(pattern).test(fileName),
    )
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
    pipFilePatterns.some((pattern) => new RegExp(pattern).test(fileName)) ||
    pythonMetadataFilesRegex.test(filePath) ||
    deletedPipAppFilesPatterns.some((pattern) =>
      new RegExp(pattern).test(fileName),
    )
  );
}

export const getPipAppFileContentAction: ExtractAction = {
  actionName: "pip-app-files",
  filePathMatches: pipFilePathMatches,
  callback: streamToString,
};
