import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../types";

export function analyze(
  targetImage: string,
  spdxFileContents: string[],
): Promise<ImagePackagesAnalysis> {
  // TODO: implement
  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Spdx,
    Analysis: [],
  });
}

function parseSpdxFile(text: string): AnalyzedPackageWithVersion[] {
  // TODO: implement
  return [];
}

function parseSpdxLine(pkg: any): AnalyzedPackageWithVersion {
  // TODO: implement
  return {
    Name: "",
    Version: "",
    Source: undefined,
    Provides: [],
    Deps: {},
    AutoInstalled: undefined,
  };
}

function stripDhiPrefix(name: string): string {
  // TODO: implement
  return name;
}

function extractPurl(pkg: any): string | undefined {
  // TODO: implement
  return undefined;
}

function createDhiPurl(name: string, version: string): string {
  // TODO: implement
  return "";
}
