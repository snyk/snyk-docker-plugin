import {
  FilePathToBuffer,
  FilePathToContent,
  FilePathToElfContent,
} from "../analyzer/applications/types";
import { ExtractedLayers, FileContent } from "../extractor/types";
import { Elf } from "../go-parser/types";

export function getContent(
  extractedLayers: ExtractedLayers,
  searchedAction: string,
  contentTypeValidation: (type: FileContent) => boolean,
): FilePathToContent {
  const foundAppFiles = {};

  for (const filePath of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[filePath])) {
      if (actionName !== searchedAction) {
        continue;
      }
      if (!contentTypeValidation(extractedLayers[filePath][actionName])) {
        throw new Error("unexpected content type");
      }
      foundAppFiles[filePath] = extractedLayers[filePath][actionName];
    }
  }

  return foundAppFiles;
}

function isStringType(type: FileContent) {
  return typeof type === "string";
}

export function getFileContent(
  extractedLayers: ExtractedLayers,
  searchedAction: string,
): FilePathToContent {
  let foundAppFiles;
  try {
    foundAppFiles = getContent(extractedLayers, searchedAction, isStringType);
  } catch {
    throw new Error("expected string");
  }

  return foundAppFiles;
}

function isElfType(type: FileContent): type is Elf {
  const elf = type as Elf;
  return !!(elf.body && elf.body.programs && elf.body.sections);
}

export function getElfFileContent(
  extractedLayers: ExtractedLayers,
  searchedAction: string,
): FilePathToElfContent {
  let foundAppFiles;
  try {
    foundAppFiles = getContent(extractedLayers, searchedAction, isElfType);
  } catch {
    throw new Error("elf file expected to contain programs and sections");
  }

  return foundAppFiles;
}

function isTypeBuffer(type: FileContent) {
  return Buffer.isBuffer(type);
}

export function getBufferContent(
  extractedLayers: ExtractedLayers,
  searchedAction: string,
): FilePathToBuffer {
  let foundAppFiles;
  try {
    foundAppFiles = getContent(extractedLayers, searchedAction, isTypeBuffer);
  } catch {
    throw new Error("expected Buffer");
  }

  return foundAppFiles;
}
