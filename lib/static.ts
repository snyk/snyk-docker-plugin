import { DepGraph } from "@snyk/dep-graph";
import * as analyzer from "./analyzer";
import {
  AnalyzedPackage,
  Binary,
  OSRelease,
  StaticAnalysis,
} from "./analyzer/types";
import { buildGraph } from "./dependency-graph";
import { DockerFileAnalysis } from "./dockerfile/types";
import { isTrue } from "./option-utils";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import { ImageType, PluginOptions, PluginResponse } from "./types";

export async function analyzeStatically(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  imagePath: string,
  globsToFind: { include: string[]; exclude: string[] },
  options: Partial<PluginOptions>,
): Promise<PluginResponse> {
  const staticAnalysis = await analyzer.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    imageType,
    imagePath,
    globsToFind,
    options,
  );

  const parsedAnalysisResult: {
    imageId: string;
    platform: string | undefined;
    targetOS: OSRelease;
    type: any;
    depInfosList: AnalyzedPackage[] | Binary[];
    imageLayers: string[];
  } = parseAnalysisResults(targetImage, staticAnalysis);

  const depGraph = await buildGraph(
    targetImage,
    parsedAnalysisResult.targetOS,
    parsedAnalysisResult.type,
    parsedAnalysisResult.depInfosList,
  );

  const analysis: StaticAnalysis & {
    depGraph: DepGraph;
    packageManager: string;
    targetOS: OSRelease;
  } = {
    ...staticAnalysis,
    depGraph,
    imageId: parsedAnalysisResult.imageId,
    imageLayers: parsedAnalysisResult.imageLayers,
    packageManager: parsedAnalysisResult.type,
    targetOS: parsedAnalysisResult.targetOS,
  };

  const excludeBaseImageVulns = isTrue(options["exclude-base-image-vulns"]);
  return buildResponse(analysis, dockerfileAnalysis, excludeBaseImageVulns);
}
