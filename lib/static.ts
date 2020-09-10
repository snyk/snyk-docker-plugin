import { legacy } from "@snyk/dep-graph";
import * as analyzer from "./analyzer";
import { buildTree } from "./dependency-tree";
import { DockerFileAnalysis } from "./docker-file";
import { tryGetAnalysisError } from "./errors";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import { ScanOptions, ScanResult } from "./types";

export async function analyzeStatically(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options?: Partial<ScanOptions>,
): Promise<ScanResult[]> {
  const staticAnalysisOptions = getStaticAnalysisOptions(options);

  // Relevant only if using a Docker runtime. Optional, but we may consider what to put here
  // to present to the user in Snyk UI.
  const runtime = undefined;

  try {
    const staticAnalysis = await analyzer.analyzeStatically(
      targetImage,
      dockerfileAnalysis,
      staticAnalysisOptions,
    );

    const parsedAnalysisResult = parseAnalysisResults(
      targetImage,
      staticAnalysis,
    );

    const dependenciesTree = await buildTree(
      targetImage,
      parsedAnalysisResult.type,
      parsedAnalysisResult.depInfosList,
      parsedAnalysisResult.targetOS,
    );

    const depGraph = await legacy.depTreeToGraph(
      dependenciesTree,
      parsedAnalysisResult.type,
    );

    const analysis = {
      depGraph,
      package: dependenciesTree,
      packageManager: parsedAnalysisResult.type,
      imageId: parsedAnalysisResult.imageId,
      binaries: parsedAnalysisResult.binaries,
      imageLayers: parsedAnalysisResult.imageLayers,
      rootFsLayers: staticAnalysis.rootFsLayers,
      applicationDependenciesScanResults:
        staticAnalysis.applicationDependenciesScanResults,
    };

    // hacking our way through types for backwards compatibility
    return buildResponse(
      runtime,
      analysis,
      dockerfileAnalysis,
      staticAnalysis.manifestFiles,
      staticAnalysis.binaries,
      staticAnalysisOptions,
    );
  } catch (error) {
    const analysisError = tryGetAnalysisError(error, targetImage);
    throw analysisError;
  }
}

export function isRequestingStaticAnalysis(options?: any): boolean {
  return options && options.staticAnalysisOptions;
}

// TODO: this function needs to go as soon as the dynamic scanning goes
function getStaticAnalysisOptions(options: any): Partial<ScanOptions> {
  if (!options || !options.imagePath || options.imageType === undefined) {
    throw new Error("Missing required parameters for static analysis");
  }

  return {
    imagePath: options.imagePath,
    imageType: options.imageType,
    experimental: options.experimental,
    appScan: options.appScan,
    globsToFind: {
      include: options.manifestGlobs,
      exclude: options.manifestExcludeGlobs,
    },
  };
}
