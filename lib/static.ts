import { DepGraph, legacy } from "@snyk/dep-graph";
import * as analyzer from "./analyzer";
import { StaticAnalysis } from "./analyzer/types";
import { buildTree } from "./dependency-tree";
import { DockerFileAnalysis } from "./docker-file";
import { tryGetAnalysisError } from "./errors";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import { DepTree, ImageType, PluginResponse } from "./types";

export async function analyzeStatically(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  imagePath: string,
  excludeBaseImageVulns: boolean,
  globsToFind: { include: string[]; exclude: string[] },
  appScan: boolean,
): Promise<PluginResponse> {
  try {
    const staticAnalysis = await analyzer.analyzeStatically(
      targetImage,
      dockerfileAnalysis,
      imageType,
      imagePath,
      globsToFind,
      appScan,
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

    const analysis: StaticAnalysis & {
      depGraph: DepGraph;
      depTree: DepTree;
    } = {
      ...staticAnalysis,
      depGraph,
      depTree: dependenciesTree,
      imageId: parsedAnalysisResult.imageId,
      imageLayers: parsedAnalysisResult.imageLayers,
    };

    return buildResponse(analysis, dockerfileAnalysis, excludeBaseImageVulns);
  } catch (error) {
    const analysisError = tryGetAnalysisError(error, targetImage);
    throw analysisError;
  }
}
