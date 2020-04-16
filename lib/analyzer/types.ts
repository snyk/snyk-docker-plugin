import { ScanResult } from "../types";

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

export interface DockerInspectOutput {
  Id: string;
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

export interface DynamicAnalysis {
  imageId: string;
  osRelease: OSRelease;
  results: ImageAnalysis[];
  binaries: ImageAnalysis;
  imageLayers: string[];
}

export interface StaticAnalysis {
  imageId: string;
  osRelease: OSRelease;
  results: ImageAnalysis[]; // TODO: rename to imageAnalysis (or just merge to the new data structure)
  binaries: string[];
  imageLayers: string[];
  scanResults: ScanResult[]; // to replace `results`?
}
