import { ImageName } from "../extractor/image";
import { BaseRuntime } from "../facts";
import { AutoDetectedUserInstructions, ManifestFile } from "../types";
import {
  AppDepsScanResultWithoutTarget,
  JarCoords,
} from "./applications/types";

export interface AnalyzedPackage {
  Name: string;
  Version?: string;
  Source?: string;
  SourceVersion?: string;
  Provides: string[];
  Deps: {
    [name: string]: any;
  };
  Purl?: string;
  AutoInstalled?: boolean;
}
export interface AnalyzedPackageWithVersion extends AnalyzedPackage {
  Version: string;
}

export interface DockerInspectOutput {
  Architecture: string;
}

export interface ImageAnalysis {
  Image: string;
  AnalyzeType: AnalysisType;
  Analysis: AnalyzedPackage[] | Binary[];
}

export interface ImagePackagesAnalysis extends ImageAnalysis {
  AnalyzeType: Exclude<AnalysisType, AnalysisType.Binaries>;
  Analysis: AnalyzedPackageWithVersion[];
}

export enum AnalysisType {
  Apk = "Apk",
  Apt = "Apt",
  Rpm = "Rpm",
  Chisel = "Chisel",
  Binaries = "binaries",
  Linux = "linux", // default/unknown/tech-debt
}

/**
 * Per-package introducing-layer diffID, keyed by the canonical
 * dep-graph node name `<fullName>@<version>` (where `fullName` is the
 * string minted by `depFullName`: `<source>/<binary>` for OS packages
 * with a known source/origin, else `<binary>`). Value is the
 * `sha256:…` diffID of the rootfs layer that introduced the surviving
 * copy of the package.
 *
 * Shared between the producer (`computeOsLayerAttribution` and friends
 * in `lib/analyzer/layer-attribution.ts`) and the consumer
 * (`response-builder.annotateDockerLayerDiffIds`, which stamps the
 * `dockerLayerDiffId` label on each matching dep-graph node).
 */
export type IntroducingLayerByPackage = Map<string, string>;

export interface OSRelease {
  name: string;
  version: string;
  prettyName: string;
}

export interface Binary {
  name: string;
  version: string;
}

export interface IAptFiles {
  dpkgFile: string;
  extFile: string;
}

export interface JarFingerprint {
  location: string;
  digest: string | null;
  parentName?: string;
  name?: string;
  version?: string;
  dependencies: JarCoords[];
}
export interface StaticAnalysis {
  imageId: string;
  platform?: string;
  osRelease: OSRelease;
  results: ImageAnalysis[];
  binaries: string[];
  baseRuntimes?: BaseRuntime[];
  imageLayers: string[];
  rootFsLayers?: string[];
  /**
   * Per-package introducing-layer diffID. Populated only when the
   * `layer-attribution` option is enabled and an OS package manager
   * attribution succeeded.
   *
   * Consumed by `response-builder` to annotate dep-graph nodes with
   * the new `dockerLayerDiffId` label, which the backend then joins to
   * a `createdBy` instruction at read time using the duplicated
   * `rootFs` / `history` facts on the same scan result.
   */
  introducingLayerByPackage?: IntroducingLayerByPackage;
  /**
   * Non-fatal warnings produced by the layer-attribution path (e.g. the
   * image's `history` array does not align 1:1 with `rootfs.diff_ids[]`).
   * Surfaced to the user via the `pluginWarnings` fact. The per-package
   * `dockerLayerDiffId` labels remain correct; these messages flag that
   * downstream joins from diffID to Dockerfile instruction may not work.
   */
  layerAttributionWarnings?: string[];
  autoDetectedUserInstructions?: AutoDetectedUserInstructions;
  applicationDependenciesScanResults: AppDepsScanResultWithoutTarget[];
  manifestFiles: ManifestFile[];
  imageLabels?: { [key: string]: string };
  imageCreationTime?: string;
  containerConfig?: {
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
  } | null;
  history?: Array<{
    created?: string | null;
    author?: string | null;
    created_by?: string | null;
    comment?: string | null;
    empty_layer?: boolean | null;
  }> | null;
  timings?: Record<string, number>;
}

export interface StaticPackagesAnalysis extends StaticAnalysis {
  results: ImagePackagesAnalysis[];
}

export interface ArchiveResult {
  imageName: ImageName;
  path: string;
  removeArchive(): void;
}

export interface ImageDetails {
  hostname: string;
  imageName: string;
  tag: string;
}

export interface DestinationDir {
  name: string;
  removeCallback: () => void;
}

export interface SourcePackage {
  name: string;
  version: string;
  release: string;
}

export interface ChiselPackage {
  kind: "package";
  name: string;
  version: string;
  sha256: string;
  arch: string;
}
