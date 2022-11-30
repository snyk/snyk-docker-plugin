import * as analyzer from "./analyzer";
import { StaticAnalysis } from "./analyzer/types";
import { buildTree } from "./dependency-tree";
import { DockerFileAnalysis } from "./dockerfile/types";
import { isTrue } from "./option-utils";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import { DepTree, ImageType, PluginOptions, PluginResponse } from "./types";

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

  const parsedAnalysisResult = parseAnalysisResults(
    targetImage,
    staticAnalysis,
  );

  /** @deprecated Should try to build a dependency graph instead. */
  const dependenciesTree = buildTree(
    targetImage,
    parsedAnalysisResult.packageFormat,
    parsedAnalysisResult.depInfosList,
    parsedAnalysisResult.targetOS,
  );

  const analysis: StaticAnalysis & {
    depTree: DepTree;
    packageFormat: string;
  } = {
    ...staticAnalysis,
    depTree: dependenciesTree,
    imageId: parsedAnalysisResult.imageId,
    imageLayers: parsedAnalysisResult.imageLayers,
    packageFormat: parsedAnalysisResult.packageFormat,
  };

  const excludeBaseImageVulns = isTrue(options["exclude-base-image-vulns"]);
  return buildResponse(analysis, dockerfileAnalysis, excludeBaseImageVulns);
}
