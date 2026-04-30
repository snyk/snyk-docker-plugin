import * as analyzer from "./analyzer";
import { StaticAnalysis } from "./analyzer/types";
import { buildTree } from "./dependency-tree";
import { DockerFileAnalysis } from "./dockerfile/types";
import { getImageNames, ImageName } from "./extractor/image";
import {
  constructOCIDisributionMetadata,
  OCIDistributionMetadata,
} from "./extractor/oci-distribution-metadata";
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
  imageName?: ImageName,
): Promise<PluginResponse> {
  const totalStart = Date.now();

  const staticAnalysis = await analyzer.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    imageType,
    imagePath,
    globsToFind,
    options,
  );

  const depTreeStart = Date.now();

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

  const names = getImageNames(options, imageName);
  let ociDistributionMetadata: OCIDistributionMetadata | undefined;
  if (options.imageNameAndTag && options.digests?.manifest) {
    ociDistributionMetadata = constructOCIDisributionMetadata({
      imageName: options.imageNameAndTag,
      manifestDigest: options.digests.manifest,
      indexDigest: options.digests.index,
    });
  }

  const response = await buildResponse(
    analysis,
    dockerfileAnalysis,
    excludeBaseImageVulns,
    names,
    ociDistributionMetadata,
    options,
  );

  const depTreeBuildingMs = Date.now() - depTreeStart;
  const totalMs = Date.now() - totalStart;

  const timings: Record<string, number> = {
    ...staticAnalysis.timings,
    depTreeBuildingMs,
    totalMs,
  };

  return {
    ...response,
    analytics: [
      ...(response.analytics ?? []),
      {
        name: "containerPluginTimings",
        data: timings,
      },
    ],
  };
}
