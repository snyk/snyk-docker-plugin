import { Readable } from "stream";
import { Elf } from "../go-parser/types";
import { AutoDetectedUserInstructions, PluginOptions } from "../types";

export type ExtractCallback = (
  dataStream: Readable,
  streamSize?: number,
) => Promise<string | Buffer>;

export type FileContent = string | Buffer | Elf;

export type FileNameAndContent = Record<string, FileContent>;

export interface Extractor {
  extractArchive(
    fileSystemPath: string,
    extractActions: ExtractAction[],
    options: Partial<PluginOptions>,
  ): ExtractedLayersAndManifest;
  getImageIdFromManifest(
    manifest: DockerArchiveManifest | OciArchiveManifest,
  ): string;
  getManifestLayers(
    manifest: DockerArchiveManifest | OciArchiveManifest,
  ): string[];
}

export interface ExtractionResult {
  imageId: string;
  manifestLayers: string[];
  extractedLayers: ExtractedLayers;
  rootFsLayers?: string[];
  autoDetectedUserInstructions?: AutoDetectedUserInstructions;
  platform?: string;
  imageLabels?: { [key: string]: string };
  imageCreationTime?: string;
}

export interface ExtractedLayers {
  [layerName: string]: FileNameAndContent;
}

export interface ExtractedLayersAndManifest {
  layers: ExtractedLayers[];
  manifest: DockerArchiveManifest | OciArchiveManifest;
  imageConfig: ImageConfig;
}

export interface DockerArchiveManifest {
  // Usually points to the JSON file in the archive that describes how the image was built.
  Config: string;
  RepoTags: string[];
  // The names of the layers in this archive, usually in the format "<sha256>.tar" or "<sha256>/layer.tar".
  Layers: string[];
}

export interface ImageConfig {
  architecture: string;
  os: string;
  rootfs: { diff_ids: string[] };
  config: {
    Labels: { [key: string]: string };
  };
  created: string;
}

export interface OciArchiveLayer {
  digest: string;
}

export interface OciArchiveManifest {
  schemaVersion: string;
  config: { digest: string };
  layers: OciArchiveLayer[];
}

export interface OciManifestInfo {
  digest: string;
  mediaType: string;
  platform?: OciPlatformInfo;
}

export interface OciPlatformInfo {
  os?: string;
  architecture?: string;
  variant?: string;
}

export interface OciImageIndex {
  manifests: OciManifestInfo[];
}

export interface KanikoArchiveManifest {
  // Usually points to the JSON file in the archive that describes how the image was built.
  Config: string;
  RepoTags: string[];
  // The names of the layers in this archive, usually in the format "<sha256>.tar" or "<sha256>/layer.tar".
  Layers: string[];
}

export interface KanikoExtractionResult {
  imageId: string;
  manifestLayers: string[];
  extractedLayers: KanikoExtractedLayers;
  rootFsLayers?: string[];
  autoDetectedUserInstructions?: AutoDetectedUserInstructions;
  platform?: string;
  imageLabels?: { [key: string]: string };
  imageCreationTime?: string;
}

export interface KanikoExtractedLayers {
  [layerName: string]: FileNameAndContent;
}

export interface KanikoExtractedLayersAndManifest {
  layers: KanikoExtractedLayers[];
  manifest: KanikoArchiveManifest;
  imageConfig: ImageConfig;
}

export interface ExtractAction {
  // This name should be unique across all actions used.
  actionName: string;
  filePathMatches: (filePath: string) => boolean;
  // Applies the given callback once a file match is found given the pattern above.
  // The idea is that the file content can be transformed in any way.
  callback?: ExtractCallback;
}

export interface DetectedImageLayers {
  packages;
  layers;
}
