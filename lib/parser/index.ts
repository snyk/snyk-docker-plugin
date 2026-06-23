import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
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

/**
 * Selects the single OS-package analysis that represents the image, using
 * the "first non-empty result wins" rule. The OS dep graph is built from
 * exactly this one analysis (see `parseAnalysisResults`), so any other
 * producer that needs to agree with the dep graph on "which OS package
 * manager is this image?" — e.g. layer attribution — must select through
 * here rather than re-deriving its own answer, to avoid drift.
 *
 * Returns `undefined` for scratch / unknown-PM images (no non-empty result).
 */
export function selectPrimaryPackageAnalysis(
  results: ImagePackagesAnalysis[],
): ImagePackagesAnalysis | undefined {
  return results.find((res) => res.Analysis && res.Analysis.length > 0);
}

export function parseAnalysisResults(
  targetImage: string,
  analysis: StaticPackagesAnalysis,
): AnalysisInfo {
  let analysisResult: ImagePackagesAnalysis | undefined =
    selectPrimaryPackageAnalysis(analysis.results);

  if (!analysisResult) {
    // Special case when we have no package management
    // on scratch images or images with unknown package manager
    analysisResult = {
      Image: targetImage,
      AnalyzeType: AnalysisType.Linux,
      Analysis: [],
    };
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
