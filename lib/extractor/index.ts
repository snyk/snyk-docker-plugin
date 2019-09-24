import { extractDockerArchiveLayers } from "./layer";
import { ExtractAction, ExtractedLayers } from "./types";

/**
 * Given a path on the file system to a docker-archive, open it up to inspect the layers
 * and look for specific files. File content can be transformed with a custom callback function if needed.
 * @param fileSystemPath Path to an existing docker-archive.
 * @param extractActions This denotes a file pattern to look for and how to transform the file if it is found.
 * By default the file is returned raw if no processing is desired.
 */
async function getDockerArchiveLayers(
  fileSystemPath: string,
  extractActions: ExtractAction[],
): Promise<ExtractedLayers> {
  const layers = await extractDockerArchiveLayers(
    fileSystemPath,
    extractActions,
  );

  if (!layers) {
    return {};
  }

  const result: ExtractedLayers = {};

  // TODO: This removes the information about the layer name, maybe we would need it in the future?

  for (const layer of layers) {
    // go over extracted files products found in this layer
    for (const filename of Object.keys(layer)) {
      // file was not found
      if (!Reflect.has(result, filename)) {
        result[filename] = layer[filename];
      }
    }
  }

  return result;
}

export { extractDockerArchiveLayers, getDockerArchiveLayers };
