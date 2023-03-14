import {
  getLayersFromPackages,
  getPackagesFromRunInstructions,
} from "../dockerfile/instruction-parser";
import { AutoDetectedUserInstructions, ImageType } from "../types";
import * as dockerExtractor from "./docker-archive";
import * as ociExtractor from "./oci-archive";
import {
  DockerArchiveManifest,
  ExtractAction,
  ExtractedLayers,
  ExtractedLayersAndManifest,
  ExtractionResult,
  Extractor,
  FileContent,
  ImageConfig,
  OciArchiveManifest,
} from "./types";

export class InvalidArchiveError extends Error {
  constructor(message) {
    super();
    this.name = "InvalidArchiveError";
    this.message = message;
  }
}
class ArchiveExtractor {
  private extractor: Extractor;
  private fileSystemPath: string;
  private extractActions: ExtractAction[];

  constructor(extractor: Extractor, path: string, actions: ExtractAction[]) {
    this.fileSystemPath = path;
    this.extractActions = actions;
    this.extractor = extractor;
  }

  public getExtractor(): Extractor {
    return this.extractor;
  }

  public async getLayersAndManifest(): Promise<ExtractedLayersAndManifest> {
    return await this.extractor.extractArchive(
      this.fileSystemPath,
      this.extractActions,
    );
  }

  public getImageIdFromManifest(
    manifest: DockerArchiveManifest | OciArchiveManifest,
  ) {
    return this.extractor.getImageIdFromManifest(manifest);
  }

  public getManifestLayers(
    manifest: DockerArchiveManifest | OciArchiveManifest,
  ) {
    return this.extractor.getManifestLayers(manifest);
  }
}

/**
 * Given a path on the file system to a image archive, open it up to inspect the layers
 * and look for specific files. File content can be transformed with a custom callback function if needed.
 * @param fileSystemPath Path to an existing archive.
 * @param extractActions This denotes a file pattern to look for and how to transform the file if it is found.
 * By default the file is returned raw if no processing is desired.
 */
export async function extractImageContent(
  imageType: ImageType,
  fileSystemPath: string,
  extractActions: ExtractAction[],
): Promise<ExtractionResult> {
  const extractors = new Map<ImageType, ArchiveExtractor>([
    [
      ImageType.DockerArchive,
      new ArchiveExtractor(
        dockerExtractor as unknown as Extractor,
        fileSystemPath,
        extractActions,
      ),
    ],
    [
      ImageType.OciArchive,
      new ArchiveExtractor(
        ociExtractor as unknown as Extractor,
        fileSystemPath,
        extractActions,
      ),
    ],
  ]);

  let extractor: ArchiveExtractor;
  let archiveContent: ExtractedLayersAndManifest;

  if (extractors.has(imageType)) {
    extractor = extractors.get(imageType) as ArchiveExtractor;
    archiveContent = await extractor.getLayersAndManifest();
  } else {
    // At this stage we do not know the format of the image so we will attempt
    // to extract the archive using the dockerExtractor but fall back to use the
    // ociExtractor if we encounter an invalid format.
    // This will happen on images pulled by the docker binary when using
    // containerd under the hood
    // @see https://snyksec.atlassian.net/browse/LUM-147
    try {
      extractor = extractors.get(ImageType.DockerArchive) as ArchiveExtractor;
      archiveContent = await extractor.getLayersAndManifest();
    } catch (err) {
      if (err instanceof InvalidArchiveError) {
        extractor = extractors.get(ImageType.OciArchive) as ArchiveExtractor;
        archiveContent = await extractor.getLayersAndManifest();
      } else {
        throw err;
      }
    }
  }

  return {
    imageId: extractor.getImageIdFromManifest(archiveContent.manifest),
    manifestLayers: extractor.getManifestLayers(archiveContent.manifest),
    imageCreationTime: archiveContent.imageConfig.created,
    extractedLayers: layersWithLatestFileModifications(archiveContent.layers),
    rootFsLayers: getRootFsLayersFromConfig(archiveContent.imageConfig),
    autoDetectedUserInstructions: getDetectedLayersInfoFromConfig(
      archiveContent.imageConfig,
    ),
    platform: getPlatformFromConfig(archiveContent.imageConfig),
    imageLabels: archiveContent.imageConfig.config.Labels,
  };
}

export function getRootFsLayersFromConfig(imageConfig: ImageConfig): string[] {
  try {
    return imageConfig.rootfs.diff_ids;
  } catch (err) {
    throw new Error("Failed to extract rootfs array from image config");
  }
}

export function getPlatformFromConfig(
  imageConfig: ImageConfig,
): string | undefined {
  return imageConfig.os && imageConfig.architecture
    ? `${imageConfig.os}/${imageConfig.architecture}`
    : undefined;
}

export function getDetectedLayersInfoFromConfig(
  imageConfig,
): AutoDetectedUserInstructions {
  const runInstructions = getUserInstructionLayersFromConfig(imageConfig)
    .filter((instruction) => !instruction.empty_layer && instruction.created_by)
    .map((instruction) => instruction.created_by.replace("# buildkit", ""));

  const dockerfilePackages = getPackagesFromRunInstructions(runInstructions);
  const dockerfileLayers = getLayersFromPackages(dockerfilePackages);
  return { dockerfilePackages, dockerfileLayers };
}

export function getUserInstructionLayersFromConfig(imageConfig) {
  const diffInHours = (d1, d2) => Math.abs(d1 - d2) / 1000 / (60 * 60);
  const maxDiffInHours = 5;

  const history = imageConfig.history;
  if (!history) {
    return [];
  }
  const lastInstructionTime = new Date(history.slice(-1)[0].created);
  const userInstructionLayers = history.filter((layer) => {
    return (
      diffInHours(new Date(layer.created), lastInstructionTime) <=
      maxDiffInHours
    );
  });
  // should only happen if there are no layers created by user instructions
  if (userInstructionLayers.length === history.length) {
    return [];
  }
  return userInstructionLayers;
}

function layersWithLatestFileModifications(
  layers: ExtractedLayers[],
): ExtractedLayers {
  const extractedLayers: ExtractedLayers = {};
  const removedFilesToIgnore: Set<string> = new Set();

  // TODO: This removes the information about the layer name, maybe we would need it in the future?
  for (const layer of layers) {
    // go over extracted files products found in this layer
    for (const filename of Object.keys(layer)) {
      // if finding a deleted file - trimming to its original file name for excluding it from extractedLayers
      if (isDeletedFile(filename)) {
        removedFilesToIgnore.add(filename.replace(/.wh./, ""));
      }

      // not adding the original file to extractedLayers
      // and removing it from the set since it can be found in consecutive layers
      if (removedFilesToIgnore.has(filename)) {
        removedFilesToIgnore.delete(filename);
      } else if (
        // file was not found + avoid adding deleted files with .wh.
        !Reflect.has(extractedLayers, filename) &&
        !isDeletedFile(filename)
      ) {
        extractedLayers[filename] = layer[filename];
      }
    }
  }
  return extractedLayers;
}

export function isDeletedFile(filename: string) {
  return filename.match(/.wh./gm);
}

function isBufferType(type: FileContent): type is Buffer {
  return (type as Buffer).buffer !== undefined;
}

function isStringType(type: FileContent): type is string {
  return (type as string).substring !== undefined;
}

export function getContentAsBuffer(
  extractedLayers: ExtractedLayers,
  extractAction: ExtractAction,
): Buffer | undefined {
  const content = getContent(extractedLayers, extractAction);
  return content !== undefined && isBufferType(content) ? content : undefined;
}

export function getContentAsString(
  extractedLayers: ExtractedLayers,
  extractAction: ExtractAction,
): string | undefined {
  const content = getContent(extractedLayers, extractAction);
  return content !== undefined && isStringType(content) ? content : undefined;
}

function getContent(
  extractedLayers: ExtractedLayers,
  extractAction: ExtractAction,
): FileContent | undefined {
  const fileNames = Object.keys(extractedLayers);
  const fileNamesProducedByTheExtractAction = fileNames.filter(
    (name) => extractAction.actionName in extractedLayers[name],
  );

  const firstFileNameMatch = fileNamesProducedByTheExtractAction.find((match) =>
    extractAction.filePathMatches(match),
  );

  return firstFileNameMatch !== undefined
    ? extractedLayers[firstFileNameMatch][extractAction.actionName]
    : undefined;
}
