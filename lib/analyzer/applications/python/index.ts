import { ExtractedLayers } from "../../../extractor/types";
import { getFileContent } from "../../../inputs";
import {
  getPipAppFileContentAction,
  getPoetryAppFileContentAction,
  getPythonAppFileContentAction,
} from "../../../inputs/python/static";
import { getApplicationFiles } from "../runtime-common";
import { EcosystemScanner, ScanContext } from "../types";
import { pipFilesToScannedProjects } from "./pip";
import { poetryFilesToScannedProjects } from "./poetry";

export { pipFilesToScannedProjects, poetryFilesToScannedProjects };

export const poetryScanner: EcosystemScanner = {
  name: "poetry",
  timingKey: "poetryAnalysisMs",
  isEnabled: () => true,
  actions: () => [getPoetryAppFileContentAction],
  scan: (extractedLayers: ExtractedLayers) =>
    poetryFilesToScannedProjects(
      getFileContent(extractedLayers, getPoetryAppFileContentAction.actionName),
    ),
};

export const pipScanner: EcosystemScanner = {
  name: "pip",
  timingKey: "pipAnalysisMs",
  isEnabled: () => true,
  actions: () => [getPipAppFileContentAction],
  scan: (extractedLayers: ExtractedLayers) =>
    pipFilesToScannedProjects(
      getFileContent(extractedLayers, getPipAppFileContentAction.actionName),
    ),
};

export const pythonApplicationFilesScanner: EcosystemScanner = {
  name: "pythonAppFiles",
  timingKey: "pipAnalysisMs",
  isEnabled: (ctx: ScanContext) => ctx.collectApplicationFiles,
  actions: () => [getPythonAppFileContentAction],
  scan: async (extractedLayers: ExtractedLayers) =>
    getApplicationFiles(
      getFileContent(extractedLayers, getPythonAppFileContentAction.actionName),
      "python",
      "python",
    ),
};
