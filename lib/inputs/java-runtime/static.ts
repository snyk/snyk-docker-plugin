import { normalize as normalizePath } from "path";
import { getContentAsString } from "../../extractor";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

/**
 * Extract action to detect and read the Java runtime release file.
 * This file contains metadata about the Java installation including version,
 * implementor, image type (JRE/JDK), and modules (important for jlink custom JREs).
 */
export const getJavaRuntimeReleaseAction: ExtractAction = {
  actionName: "java-runtime-release",
  // using this specific path for Java runtime metadata for now, but might want to expand this to other paths in the future.
  // Different implementors (Oracle, Eclipse Adoptium, etc.) may use different paths. This path is confirmed for Eclipse Adoptium.
  filePathMatches: (filePath) =>
    filePath === normalizePath("/opt/java/openjdk/release"),
  callback: streamToString,
};

/**
 * Retrieves the Java runtime release file content from extracted layers.
 * Returns the raw file content as a string, or an empty string if not found.
 */
export function getJavaRuntimeReleaseContent(
  extractedLayers: ExtractedLayers,
): string {
  const content = getContentAsString(
    extractedLayers,
    getJavaRuntimeReleaseAction,
  );
  return content || "";
}

