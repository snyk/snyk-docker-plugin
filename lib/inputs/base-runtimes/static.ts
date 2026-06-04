import { basename, normalize as normalizePath } from "path";
import { getContentAsString } from "../../extractor";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

function javaReleaseFilePathMatches(filePath: string): boolean {
  const p = normalizePath(filePath);
  const isReleaseFile = basename(p) === "release";
  const matched =
    // eclipse-temurin: /opt/java/openjdk/release
    p === normalizePath("/opt/java/openjdk/release") ||
    // official Docker openjdk: /usr/local/openjdk-<version>/release
    (p.startsWith(normalizePath("/usr/local/openjdk-")) && isReleaseFile) ||
    // Debian/Ubuntu default-jdk: /usr/lib/jvm/java-<version>-openjdk-<arch>/release
    (p.startsWith(normalizePath("/usr/lib/jvm/java-")) && isReleaseFile) ||
    // Oracle JDK: /usr/java/<version>/release
    (p.startsWith(normalizePath("/usr/java/")) && isReleaseFile);
  return matched;
}

export const getJavaRuntimeReleaseAction: ExtractAction = {
  actionName: "java-runtime-release",
  filePathMatches: javaReleaseFilePathMatches,
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
