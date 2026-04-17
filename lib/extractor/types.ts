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
  provenanceAttestations?: ProvenanceAttestation[];
}

export interface ExtractedLayers {
  [layerName: string]: FileNameAndContent;
}

export interface ExtractedLayersAndManifest {
  layers: ExtractedLayers[];
  manifest: DockerArchiveManifest | OciArchiveManifest;
  imageConfig: ImageConfig;
  provenanceAttestations?: ProvenanceAttestation[];
}

export interface DockerArchiveManifest {
  // Usually points to the JSON file in the archive that describes how the image was built.
  Config: string;
  RepoTags: string[];
  // The names of the layers in this archive, usually in the format "<sha256>.tar" or "<sha256>/layer.tar".
  Layers: string[];
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
  mediaType?: string;
  size?: number;
  annotations?: Record<string, string>;
}

export interface OciArchiveManifest {
  schemaVersion: string;
  mediaType?: string;
  config: { digest: string; mediaType?: string };
  layers: OciArchiveLayer[];
  annotations?: Record<string, string>;
}

export interface OciManifestInfo {
  digest: string;
  mediaType: string;
  size?: number;
  platform?: OciPlatformInfo;
  annotations?: Record<string, string>;
}

export interface OciPlatformInfo {
  os?: string;
  architecture?: string;
  variant?: string;
}

export interface OciImageIndex {
  mediaType?: string;
  manifests: OciManifestInfo[];
}

export interface InTotoStatement {
  _type?: string;
  subject?: Array<{
    name?: string;
    digest?: Record<string, string>;
  }>;
  predicateType?: string;
  predicate?: Record<string, unknown>;
}

/**
 * https://github.com/opencontainers/image-spec/blob/main/image-index.md
 * https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
 * https://slsa.dev/provenance/v1
 */
export interface ProvenanceAttestation {
  attestationManifestDigest: string;
  mediaType: string;
  annotations: Record<string, string>;
  provenanceLayers: Array<{
    digest: string;
    mediaType?: string;
    annotations?: Record<string, string>;
    inTotoStatement?: InTotoStatement;
  }>;
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
