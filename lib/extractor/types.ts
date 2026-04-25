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
  containerConfig?: ContainerConfig | null;
  history?: HistoryEntry[] | null;
}

export interface ExtractedLayers {
  [layerName: string]: FileNameAndContent;
}

export interface TarArchiveManifest {
  // Usually points to the JSON file in the archive that describes how the image was built.
  Config: string;
  RepoTags: string[];
  // The names of the layers in this archive, usually in the format "<sha256>.tar" or "<sha256>/layer.tar".
  Layers: string[];
}

// tslint:disable-next-line:no-empty-interface
export interface DockerArchiveManifest extends TarArchiveManifest {}

// tslint:disable-next-line:no-empty-interface
export interface KanikoArchiveManifest extends TarArchiveManifest {}

export interface ExtractedLayersAndManifest {
  layers: ExtractedLayers[];
  manifest: TarArchiveManifest | OciArchiveManifest;
  imageConfig: ImageConfig;
  annotations?: { [key: string]: string };
}

export interface ContainerConfig {
  User?: string | null;
  ExposedPorts?: { [port: string]: object } | null;
  Env?: string[] | null;
  Entrypoint?: string[] | null;
  Cmd?: string[] | null;
  Volumes?: { [path: string]: object } | null;
  WorkingDir?: string | null;
  Labels?: { [key: string]: string };
  StopSignal?: string | null;
  ArgsEscaped?: boolean | null;
}

export interface HistoryEntry {
  created?: string | null;
  author?: string | null;
  created_by?: string | null;
  comment?: string | null;
  empty_layer?: boolean | null;
}

export interface ImageConfig {
  architecture: string;
  os: string;
  rootfs: { diff_ids: string[] };
  config: ContainerConfig | null;
  created: string;
  history?: HistoryEntry[] | null;
}

export interface OciArchiveLayer {
  digest: string;
}

export interface OciArchiveManifest {
  schemaVersion: string;
  config: { digest: string };
  layers: OciArchiveLayer[];
  annotations?: { [key: string]: string };
}

export interface OciManifestInfo {
  digest: string;
  mediaType: string;
  platform?: OciPlatformInfo;
  annotations?: { [key: string]: string };
}

export interface OciPlatformInfo {
  os?: string;
  architecture?: string;
  variant?: string;
}

export interface OciImageIndex {
  manifests: OciManifestInfo[];
  annotations?: { [key: string]: string };
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
