import {
  FilePathToBuffer,
  FilePathToContent,
  FilePathToElfContent,
} from "../analyzer/applications/types";
import { ExtractedLayers, FileContent } from "../extractor/types";
import { Elf } from "../go-parser/types";

function isStringType(type: FileContent) {
  return typeof type === "string";
}

export function getFileContent(
  extractedLayers: ExtractedLayers,
  searchedAction: string,
): FilePathToContent {
  const foundAppFiles = {};

  for (const filePath of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[filePath])) {
      if (actionName !== searchedAction) {
        continue;
      }
      if (!isStringType(extractedLayers[filePath][actionName])) {
        throw new Error("expected string");
      }
      foundAppFiles[filePath] = extractedLayers[filePath][actionName];
    }
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
  const foundAppFiles = {};

  for (const filePath of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[filePath])) {
      if (actionName !== searchedAction) {
        continue;
      }

      if (!isElfType(extractedLayers[filePath][actionName])) {
        throw new Error("elf file expected to contain programs and sections");
      }

      foundAppFiles[filePath] = extractedLayers[filePath][actionName];
    }
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
  const foundAppFiles = {};

  for (const filePath of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[filePath])) {
      if (actionName !== searchedAction) {
        continue;
      }
      if (!isTypeBuffer(extractedLayers[filePath][actionName])) {
        throw new Error("expected Buffer");
      }
      foundAppFiles[filePath] = extractedLayers[filePath][actionName];
    }
  }

  return foundAppFiles;
}
