import { Readable } from "stream";

export type ExtractCallback = (
  dataStream: Readable,
) => Promise<string | Buffer>;

export type FileNameAndContent = Record<string, string | Buffer>;

export interface ExtractionResult {
  imageId: string;
  manifestLayers: string[];
  extractedLayers: ExtractedLayers;
  rootFsLayers?: string[];
}

export interface ExtractedLayers {
  [layerName: string]: FileNameAndContent;
}

export interface ExtractedLayersAndManifest {
  layers: ExtractedLayers[];
  manifest: DockerArchiveManifest;
  imageConfig: DockerArchiveImageConfig;
}

export interface DockerArchiveManifest {
  // Usually points to the JSON file in the archive that describes how the image was built.
  Config: string;
  RepoTags: string[];
  // The names of the layers in this archive, usually in the format "<sha256>.tar" or "<sha256>/layer.tar".
  Layers: string[];
}

export interface DockerArchiveImageConfig {
  rootfs: { diff_ids: string[] };
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
  platform?: { architecture: string; os: string };
}

export interface OciImageIndex {
  manifests: OciManifestInfo[];
}

export interface ExtractAction {
  // This name should be unique across all actions used.
  actionName: string;
  filePathMatches: (filePath: string) => boolean;
  // Applies the given callback once a file match is found given the pattern above.
  // The idea is that the file content can be transformed in any way.
  callback?: ExtractCallback;
}
