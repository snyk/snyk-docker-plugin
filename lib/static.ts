import * as Debug from "debug";
import * as analyzer from "./analyzer";
import { extractImageDetails } from "./analyzer/image-inspector";
import { StaticAnalysis } from "./analyzer/types";
import { buildTree } from "./dependency-tree";
import { DockerFileAnalysis } from "./dockerfile/types";
import { getErrorMessage } from "./error-utils";
import { getImageNames, ImageName } from "./extractor/image";
import {
  fetchAttestationsFromRegistry,
  parsePlatform,
} from "./extractor/fetch-registry-provenance-attestations";
import {
  constructOCIDisributionMetadata,
  OCIDistributionMetadata,
} from "./extractor/oci-distribution-metadata";
import { isTrue } from "./option-utils";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import { DepTree, ImageType, PluginOptions, PluginResponse } from "./types";

const debug = Debug("snyk");

export async function analyzeStatically(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  imagePath: string,
  globsToFind: { include: string[]; exclude: string[] },
  options: Partial<PluginOptions>,
  imageName?: ImageName,
  pulledFromRegistry = false,
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

  // Only reach back out to the registry for an image that actually came from one.
  // An Identifier reference merely *looks* like a registry reference: an image that
  // was built or loaded locally and tagged `my-registry.local/app:tag` never touched
  // a registry, and that host may not resolve at all. Attempting it there produces a
  // transport failure rather than a "no attestations" answer, and while this function
  // swallows that error, the failed request is still visible to the HTTP layer that
  // carried it -- which can append a second error document to an otherwise successful
  // `--json` result. Skipping the request avoids the failure instead of handling it.
  if (
    imageType === ImageType.Identifier &&
    pulledFromRegistry &&
    (!analysis.attestations || analysis.attestations.length === 0)
  ) {
    try {
      const {
        hostname,
        imageName: repo,
        tag,
      } = extractImageDetails(targetImage);
      analysis.attestations = await fetchAttestationsFromRegistry({
        registryBase: hostname,
        repo,
        imageReference: tag,
        username: options.username,
        password: options.password,
        platform: parsePlatform(options.platform),
      });
    } catch (error) {
      // Best-effort: provenance is optional; never fail the scan over it.
      debug(
        `[provenance] failed to fetch attestations from registry for ${targetImage}: ${getErrorMessage(
          error,
        )}`,
      );
    }
  }

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
