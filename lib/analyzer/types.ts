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
}

export interface OSRelease {
  name: string;
  version: string;
}

export interface Binary {
  name: string;
  version: string;
}
