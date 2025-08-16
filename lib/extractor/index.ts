import path = require("path");
import {
  getLayersFromPackages,
  getPackagesFromRunInstructions,
} from "../dockerfile/instruction-parser";
import { AutoDetectedUserInstructions, ImageType } from "../types";
import { PluginOptions } from "../types";
import * as dockerExtractor from "./docker-archive";
import * as kanikoExtractor from "./kaniko-archive";
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
  private options: Partial<PluginOptions>;

  constructor(
    extractor: Extractor,
    path: string,
    actions: ExtractAction[],
    options: Partial<PluginOptions>,
  ) {
    this.fileSystemPath = path;
    this.extractActions = actions;
    this.extractor = extractor;
    this.options = options;
  }

  public getExtractor(): Extractor {
    return this.extractor;
  }

  public async getLayersAndManifest(): Promise<ExtractedLayersAndManifest> {
    return await this.extractor.extractArchive(
      this.fileSystemPath,
      this.extractActions,
      this.options,
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
  options: Partial<PluginOptions>,
): Promise<ExtractionResult> {
  const extractors = new Map<ImageType, ArchiveExtractor>([
    [
      ImageType.DockerArchive,
      new ArchiveExtractor(
        dockerExtractor as unknown as Extractor,
        fileSystemPath,
        extractActions,
        options,
      ),
    ],
    [
      ImageType.OciArchive,
      new ArchiveExtractor(
        ociExtractor as unknown as Extractor,
        fileSystemPath,
        extractActions,
        options,
      ),
    ],
    [
      ImageType.KanikoArchive,
      new ArchiveExtractor(
        kanikoExtractor as unknown as Extractor,
        fileSystemPath,
        extractActions,
        options,
      ),
    ],
  ]);

  let extractor: ArchiveExtractor;
  let archiveContent: ExtractedLayersAndManifest;

  if (!extractors.has(imageType)) {
    // default to Docker extractor if image type is unknown
    imageType = ImageType.DockerArchive;
  }
  extractor = extractors.get(imageType) as ArchiveExtractor;

  try {
    archiveContent = await extractor.getLayersAndManifest();
  } catch (err) {
    if (err instanceof InvalidArchiveError) {
      // fallback to the other extractor if layer extraction failed
      [archiveContent, extractor] = await extractArchiveContentFallback(
        extractors,
      );
    } else {
      throw err;
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

async function extractArchiveContentFallback(
  extractors: Map<ImageType, ArchiveExtractor>,
): Promise<[ExtractedLayersAndManifest, ArchiveExtractor]> {
  for (const extractor of extractors.values()) {
    try {
      return [await extractor.getLayersAndManifest(), extractor];
    } catch (error) {
      continue;
    }
  }

  throw new InvalidArchiveError(
    `Unsupported archive type. Please use a Docker archive, OCI image layout, or Kaniko-compatible tarball.`,
  );
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
  return imageConfig?.os && imageConfig?.architecture
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
      // + not adding this file
      if (isWhitedOutFile(filename)) {
        removedFilesToIgnore.add(filename.replace(/\.wh\./, ""));
        continue;
      }
      // not adding previously found to be whited out files to extractedLayers
      if (removedFilesToIgnore.has(filename)) {
        continue;
      }
      // not adding path that has removed path as parent
      if (isFileInARemovedFolder(filename, removedFilesToIgnore)) {
        continue;
      }
      // file not already in extractedLayers
      if (!Reflect.has(extractedLayers, filename)) {
        extractedLayers[filename] = layer[filename];
      }
    }
  }
  return extractedLayers;
}

/**
 * check if a file is 'whited out', which is shown by
 * prefixing the filename with a .wh.
 * https://www.madebymikal.com/interpreting-whiteout-files-in-docker-image-layers/
 */
export function isWhitedOutFile(filename: string) {
  return filename.includes(".wh.");
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

function isFileInFolder(file: string, folder: string): boolean {
  const folderPath = path.normalize(folder);
  const filePath = path.normalize(file);

  return filePath.startsWith(path.join(folderPath, path.sep));
}

function isFileInARemovedFolder(
  filename: string,
  removedFilesToIgnore: Set<string>,
): boolean {
  return Array.from(removedFilesToIgnore).some((removedFile) =>
    isFileInFolder(filename, removedFile),
  );
}
