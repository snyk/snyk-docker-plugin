import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToJson } from "../../stream-utils";

export const getRedHatRepositoriesContentAction: ExtractAction = {
  actionName: "redhat-content-manifests",
  filePathMatches: isRedHatContentManifest,
  callback: streamToJson,
};

export function getRedHatRepositoriesFromExtractedLayers(
  extractedLayers: ExtractedLayers,
): string[] {
  const repositories: string[] = [];
  for (const filePath in extractedLayers) {
    if (isRedHatContentManifest(filePath)) {
      const contentManifest = extractedLayers[filePath][
        "redhat-content-manifests"
      ] as any;
      repositories.push(...contentManifest?.content_sets);
    }
  }

  return [...new Set(repositories)];
}

function isRedHatContentManifest(filePath: string): boolean {
  return filePath.startsWith("/root/buildinfo/content_manifests/");
}
