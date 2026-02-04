import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  OSRelease,
  StaticPackagesAnalysis,
} from "../analyzer/types";

export interface AnalysisInfo {
  imageId: string;
  platform: string | undefined;
  targetOS: OSRelease;
  packageFormat: string;
  depInfosList: AnalyzedPackageWithVersion[];
  imageLayers: string[];
}

export function parseAnalysisResults(
  targetImage: string,
  analysis: StaticPackagesAnalysis,
): AnalysisInfo {
  let analysisResult = analysis.results.filter((res) => {
    return (
      res.Analysis &&
      res.Analysis.length > 0 &&
      res.AnalyzeType !== AnalysisType.Spdx // In the future, we may want to abstract this to be any supplemental analysis type
    );
  })[0];

  if (!analysisResult) {
    // Special case when we have no package management
    // on scratch images or images with unknown package manager
    analysisResult = {
      Image: targetImage,
      AnalyzeType: AnalysisType.Linux,
      Analysis: [],
    };
  }

  // Merge SPDX packages into the main result
  // But skip any SPDX packages that conflict with existing package manager records
  // (apt/apk/rpm/chisel)
  const spdxResult = analysis.results.find(
    (r) => r.AnalyzeType === AnalysisType.Spdx,
  );
  if (
    spdxResult &&
    spdxResult.Analysis.length > 0 &&
    analysisResult.AnalyzeType !== AnalysisType.Spdx
  ) {
    // Create a set of existing package names from the primary package manager for fast lookup
    const existingPackageNames = new Set(
      analysisResult.Analysis.map((pkg) => pkg.Name),
    );

    // Only add SPDX packages that don't conflict with existing packages
    const nonConflictingSpdxPackages = spdxResult.Analysis.filter(
      (pkg) => !existingPackageNames.has(pkg.Name),
    );

    analysisResult.Analysis.push(...nonConflictingSpdxPackages);
  }

  let packageFormat: string;
  switch (analysisResult.AnalyzeType) {
    case AnalysisType.Apt:
    case AnalysisType.Chisel: {
      packageFormat = "deb";
      break;
    }
    default: {
      packageFormat = analysisResult.AnalyzeType.toLowerCase();
    }
  }

  return {
    imageId: analysis.imageId,
    platform: analysis.platform,
    targetOS: analysis.osRelease,
    packageFormat,
    depInfosList: analysisResult.Analysis,
    imageLayers: analysis.imageLayers,
  };
}
