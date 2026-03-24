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

function isArchiveImageType(imageType: ImageType): boolean {
  return (
    imageType === ImageType.DockerArchive ||
    imageType === ImageType.OciArchive ||
    imageType === ImageType.KanikoArchive ||
    imageType === ImageType.UnspecifiedArchiveType
  );
}

function hasUsableRepoTags(repoTags: string[] | undefined): boolean {
  if (!repoTags || repoTags.length === 0) {
    return false;
  }
  return repoTags.some((t) => t && t.trim() !== "");
}

/**
 * When scanning a TAR/OCI archive with no registry/repo tags, use the config digest
 * (imageId) as the project root identity so the CLI shows the full sha256:… (CN-928).
 */
function resolveEffectiveTargetImage(
  targetImage: string,
  imageType: ImageType,
  imageId: string | undefined,
  repoTags: string[] | undefined,
  options: Partial<PluginOptions>,
): string {
  if (options.imageNameAndTag) {
    return targetImage;
  }
  if (
    isArchiveImageType(imageType) &&
    imageId &&
    /^sha256:[a-f0-9]{64}$/i.test(imageId) &&
    !hasUsableRepoTags(repoTags)
  ) {
    return imageId;
  }
  return targetImage;
}

export async function analyzeStatically(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  imagePath: string,
  globsToFind: { include: string[]; exclude: string[] },
  options: Partial<PluginOptions>,
  imageName?: ImageName,
): Promise<PluginResponse> {
  const staticAnalysis = await analyzer.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    imageType,
    imagePath,
    globsToFind,
    options,
  );

  const effectiveTargetImage = resolveEffectiveTargetImage(
    targetImage,
    imageType,
    staticAnalysis.imageId,
    staticAnalysis.repoTags,
    options,
  );

  const parsedAnalysisResult = parseAnalysisResults(
    effectiveTargetImage,
    staticAnalysis,
  );

  /** @deprecated Should try to build a dependency graph instead. */
  const dependenciesTree = buildTree(
    effectiveTargetImage,
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

  let names = getImageNames(options, imageName);
  if (
    names.length === 0 &&
    effectiveTargetImage === staticAnalysis.imageId &&
    staticAnalysis.imageId
  ) {
    names = [staticAnalysis.imageId];
  }
  let ociDistributionMetadata: OCIDistributionMetadata | undefined;
  if (options.imageNameAndTag && options.digests?.manifest) {
    ociDistributionMetadata = constructOCIDisributionMetadata({
      imageName: options.imageNameAndTag,
      manifestDigest: options.digests.manifest,
      indexDigest: options.digests.index,
    });
  }

  return buildResponse(
    analysis,
    dockerfileAnalysis,
    excludeBaseImageVulns,
    names,
    ociDistributionMetadata,
    options,
  );
}
