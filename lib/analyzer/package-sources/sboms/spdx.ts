import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../../types";

export function analyze(
  targetImage: string,
  spdxFileContents: string[],
): Promise<ImagePackagesAnalysis> {
  const analyzedPackages: AnalyzedPackageWithVersion[] = [];

  for (const fileContent of spdxFileContents) {
    const currentPackages = parseSpdxFile(fileContent);
    analyzedPackages.push(...currentPackages);
  }

  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Spdx,
    Analysis: analyzedPackages,
  });
}

function parseSpdxFile(text: string): AnalyzedPackageWithVersion[] {
  const pkgs: AnalyzedPackageWithVersion[] = [];

  try {
    const spdxDoc = JSON.parse(text);

    if (!spdxDoc.packages || !Array.isArray(spdxDoc.packages)) {
      return pkgs;
    }

    // Usually packages.length === 1, but iterate anyway for safety
    for (const pkg of spdxDoc.packages) {
      const analyzedPkg = parseSpdxLine(pkg);
      pkgs.push(analyzedPkg);
    }
  } catch (err) {
    console.error(`Failed to parse SPDX: ${err.message}`);
  }

  return pkgs;
}

function parseSpdxLine(pkg: any): AnalyzedPackageWithVersion {
  const name = stripDhiPrefix(pkg.name);
  const version = pkg.versionInfo;
  const purl = extractPurl(pkg) || createDhiPurl(name, version);

  return {
    Name: name,
    Version: version,
    Source: undefined,
    Provides: [],
    Deps: {},
    AutoInstalled: undefined,
    Purl: purl,
  };
}

function stripDhiPrefix(name: string): string {
  return name.replace(/^dhi\//, "");
}

function extractPurl(pkg: any): string | undefined {
  if (!pkg.externalRefs || !Array.isArray(pkg.externalRefs)) {
    return undefined;
  }

  const purlRef = pkg.externalRefs.find((ref) => ref.referenceType === "purl");

  return purlRef?.referenceLocator;
}

function createDhiPurl(name: string, version: string): string {
  return `pkg:dhi/${name}@${version}`;
}
