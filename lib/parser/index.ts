import {
  AnalysisType,
  AnalyzedPackage,
  Binary,
  DynamicAnalysis,
  StaticAnalysis,
} from "../analyzer/types";

export function parseAnalysisResults(
  targetImage,
  analysis: StaticAnalysis | DynamicAnalysis,
) {
  let analysisResult = analysis.results.filter((res) => {
    return res.Analysis && res.Analysis.length > 0;
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

  let depType;
  switch (analysisResult.AnalyzeType) {
    case AnalysisType.Apt: {
      depType = "deb";
      break;
    }
    default: {
      depType = analysisResult.AnalyzeType.toLowerCase();
    }
  }

  // in the dynamic scanning flow,
  // analysis.binaries is expected to be of ImageAnalysis type.
  // in this case, we want its Analysis part which should be Binary[]
  // in the static scanning flow,
  // analysis.binaries is a string[]
  // in this case, we return `undefined` and set hashes later
  let binaries: AnalyzedPackage[] | Binary[] | undefined;
  if (analysis && analysis.binaries && !Array.isArray(analysis.binaries)) {
    binaries = analysis.binaries.Analysis;
  }

  return {
    imageId: analysis.imageId,
    targetOS: analysis.osRelease,
    type: depType,
    depInfosList: analysisResult.Analysis,
    binaries,
    imageLayers: analysis.imageLayers,
  };
}
