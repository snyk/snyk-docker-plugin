import { normalize as normalizePath } from "path";
import { getContentAsString } from "../../extractor";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

export const getJavaRuntimeReleaseAction: ExtractAction = {
  actionName: "java-runtime-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath("/opt/java/openjdk/release"),
  callback: streamToString,
};

export function getJavaRuntimeReleaseContent(
  extractedLayers: ExtractedLayers,
): string {
  const content = getContentAsString(
    extractedLayers,
    getJavaRuntimeReleaseAction,
  );
  return content || "";
}
