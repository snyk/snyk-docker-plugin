import { ExtractedLayers } from "../../extractor/types";
import { JavaRuntimeMetadata } from "../../facts";
import { getJavaRuntimeReleaseContent } from "../../inputs/java-runtime/static";
import { parseJavaRuntimeRelease } from "./parser";

/**
 * Detects Java runtime metadata from the release file.
 * This allows us to extract the Java version to scan for vulns.
 */
export function detectJavaRuntime(
  extractedLayers: ExtractedLayers,
): JavaRuntimeMetadata | null {
  const releaseContent = getJavaRuntimeReleaseContent(extractedLayers);
  return releaseContent ? parseJavaRuntimeRelease(releaseContent) : null;
}
