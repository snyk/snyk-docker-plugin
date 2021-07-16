import { DepGraph } from "@snyk/dep-graph";
import * as analyzer from "./analyzer";
import {
  AnalyzedPackage,
  Binary,
  OSRelease,
  StaticAnalysis,
} from "./analyzer/types";
import { buildGraph, pruneDepGraphIfTooManyPaths } from "./dependency-graph";
import { buildTree } from "./dependency-tree";
import { DockerFileAnalysis } from "./dockerfile/types";
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
  const staticAnalysis = await analyzer.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    imageType,
    imagePath,
    globsToFind,
    appScan,
  );

  const parsedAnalysisResult: {
    imageId: string;
    platform: string | undefined;
    targetOS: OSRelease;
    type: any;
    depInfosList: AnalyzedPackage[] | Binary[];
    imageLayers: string[];
  } = parseAnalysisResults(targetImage, staticAnalysis);

  /** @deprecated Should try to build a dependency graph instead. */
  const dependenciesTree = await buildTree(
    targetImage,
    parsedAnalysisResult.type,
    parsedAnalysisResult.depInfosList,
    parsedAnalysisResult.targetOS,
  );

  const depGraph = await buildGraph(
    targetImage,
    parsedAnalysisResult.targetOS,
    parsedAnalysisResult.type,
    parsedAnalysisResult.depInfosList,
  );

  const prunedGraph = await pruneDepGraphIfTooManyPaths(
    depGraph,
    parsedAnalysisResult.type,
  );
  // const depGraphData = prunedGraph?.toJSON() ?? depGraph.toJSON();
  // const json = JSON.stringify(depGraphData);
  // console.log(json);
  // console.log("***************");

  const analysis: StaticAnalysis & {
    depTree: DepTree;
    depGraph: DepGraph;
    packageManager: string;
  } = {
    ...staticAnalysis,
    depTree: dependenciesTree,
    depGraph: prunedGraph ?? depGraph,
    imageId: parsedAnalysisResult.imageId,
    imageLayers: parsedAnalysisResult.imageLayers,
    packageManager: parsedAnalysisResult.type,
  };

  return buildResponse(analysis, dockerfileAnalysis, excludeBaseImageVulns);
}
