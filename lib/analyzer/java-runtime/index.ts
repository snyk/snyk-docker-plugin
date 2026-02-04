import { ExtractedLayers } from "../../extractor/types";
import { BaseRuntime } from "../../facts";
import { getJavaRuntimeReleaseContent } from "../../inputs/java-runtime/static";
import { parseJavaRuntimeRelease } from "./parser";

export function detectJavaRuntime(
  extractedLayers: ExtractedLayers,
): BaseRuntime | null {
  const releaseContent = getJavaRuntimeReleaseContent(extractedLayers);
  return releaseContent ? parseJavaRuntimeRelease(releaseContent) : null;
}
