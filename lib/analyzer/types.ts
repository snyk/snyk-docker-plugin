import { ImageName } from "../extractor/image";
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
  imageLayers: string[];
  rootFsLayers?: string[];
  autoDetectedUserInstructions?: AutoDetectedUserInstructions;
  applicationDependenciesScanResults: AppDepsScanResultWithoutTarget[];
  manifestFiles: ManifestFile[];
  imageLabels?: { [key: string]: string };
  imageCreationTime?: string;
  containerConfig?: {
    User?: string | null;
    ExposedPorts?: { [port: string]: object };
    Env?: string[] | null;
    Entrypoint?: string[] | null;
    Cmd?: string[] | null;
    Volumes?: { [path: string]: object };
    WorkingDir?: string | null;
    Labels?: { [key: string]: string };
    StopSignal?: string | null;
    ArgsEscaped?: boolean;
  };
  history?: Array<{
    created?: string | null;
    author?: string | null;
    created_by?: string | null;
    comment?: string | null;
    empty_layer?: boolean;
  }>;
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
