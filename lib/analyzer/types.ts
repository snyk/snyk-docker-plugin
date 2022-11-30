import { AutoDetectedUserInstructions, ManifestFile } from "../types";
import {
  AppDepsScanResultWithoutTarget,
  JarCoords,
} from "./applications/types";

export interface AnalyzedPackage {
  Name: string;
  Version?: string;
  Source?: string;
  Provides: string[];
  Deps: {
    [name: string]: any;
  };
  AutoInstalled?: boolean;
}
export interface AnalyzedPackageWithVersion extends AnalyzedPackage {
  Version: string;
}

export interface DockerInspectOutput {
  Id: string;
  Architecture: string;
  RootFS: {
    Type: string;
    Layers: string[];
  };
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
  redHatRepositories: string[];
}

export interface StaticPackagesAnalysis extends StaticAnalysis {
  results: ImagePackagesAnalysis[];
}

export interface StaticPackagesAnalysis extends StaticAnalysis {
  results: ImagePackagesAnalysis[];
}

export interface ArchiveResult {
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
