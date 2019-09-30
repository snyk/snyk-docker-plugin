import { IAptFiles } from "../../analyzer/types";
import { getContent } from "../../extractor";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

export const getDpkgFileContentAction: ExtractAction = {
  actionName: "dpkg",
  fileNamePattern: "/var/lib/dpkg/status",
  callback: streamToString,
};

export const getExtFileContentAction: ExtractAction = {
  actionName: "ext",
  fileNamePattern: "/var/lib/apt/extended_states",
  callback: streamToString,
};

export function getAptDbFileContent(
  extractedLayers: ExtractedLayers,
): IAptFiles {
  const dpkgContent = getContent(extractedLayers, getDpkgFileContentAction);
  const dpkgFile = dpkgContent || "";

  const extContent = getContent(extractedLayers, getExtFileContentAction);
  const extFile = extContent || "";

  return {
    dpkgFile,
    extFile,
  };
}
