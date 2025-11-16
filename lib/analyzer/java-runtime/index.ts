import { JavaRuntimeMetadata } from "../../facts";
import { ExtractedLayers } from "../../extractor/types";
import { getJavaRuntimeReleaseContent } from "../../inputs/java-runtime/static";
import { parseJavaRuntimeRelease } from "./parser";

/**
 * Detects Java runtime metadata from the /opt/java/openjdk/release file.
 * This provides version, implementor, and modules information,
 * 
 * @param extractedLayers - Extracted image layers containing file contents
 * @returns Parsed Java runtime metadata or null if not found/parseable
 */
export function detectJavaRuntime(
  extractedLayers: ExtractedLayers,
): JavaRuntimeMetadata | null {
  const releaseContent = getJavaRuntimeReleaseContent(extractedLayers);

  if (!releaseContent) {
    return null;
  }

  return parseJavaRuntimeRelease(releaseContent);
}

