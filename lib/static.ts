import * as Debug from "debug";
import * as analyzer from "./analyzer";
import { extractImageDetails } from "./analyzer/image-inspector";
import { StaticAnalysis } from "./analyzer/types";
import { buildTree } from "./dependency-tree";
import { DockerFileAnalysis } from "./dockerfile/types";
import { getErrorMessage } from "./error-utils";
import {
  DistributionDigests,
  fetchDistributionDigestsFromRegistry,
} from "./extractor/fetch-registry-distribution-digests";
import {
  fetchAttestationsFromRegistry,
  keepAttestationsForManifest,
  parsePlatform,
} from "./extractor/fetch-registry-provenance-attestations";
import { getImageNames, ImageName } from "./extractor/image";
import {
  constructOCIDisributionMetadata,
  OCIDistributionMetadata,
} from "./extractor/oci-distribution-metadata";
import { resolveRegistryCredentials } from "./extractor/registry-credentials";
import { ResolvedAttestationManifest } from "./extractor/types";
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

  // Callers that pulled the image themselves (e.g. Docker Registry Agent) pass the digests in.
  let digests = options.digests;
  let digestsImageName = options.imageNameAndTag;
  if (imageType === ImageType.Identifier) {
    const registryMetadata = await fetchRegistryMetadata(
      targetImage,
      analysis,
      options,
    );
    if (registryMetadata.attestations) {
      analysis.attestations = registryMetadata.attestations;
    }
    if (!digests?.manifest && registryMetadata.digests) {
      digests = registryMetadata.digests;
      digestsImageName = targetImage;
    }
  }

  const excludeBaseImageVulns = isTrue(options["exclude-base-image-vulns"]);

  const names = getImageNames(options, imageName);
  let ociDistributionMetadata: OCIDistributionMetadata | undefined;
  if (digestsImageName && digests?.manifest) {
    ociDistributionMetadata = constructOCIDisributionMetadata({
      imageName: digestsImageName,
      manifestDigest: digests.manifest,
      indexDigest: digests.index,
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

/**
 * Fetches registry-side metadata for an image identifier scan: provenance
 * attestations and the manifest/index digests of the scanned platform.
 * Both requests use explicit credentials, falling back to `docker login`
 * credentials, and run concurrently.
 * Best-effort: this metadata is optional, so it never fails the scan.
 */
async function fetchRegistryMetadata(
  targetImage: string,
  analysis: StaticAnalysis,
  options: Partial<PluginOptions>,
): Promise<{
  attestations?: ResolvedAttestationManifest[];
  digests?: DistributionDigests;
}> {
  try {
    const { hostname, imageName: repo, tag } = extractImageDetails(targetImage);
    const credentials = await resolveRegistryCredentials(
      hostname,
      options.username,
      options.password,
    );
    const registryRef = {
      registryBase: hostname,
      repo,
      imageReference: tag,
      ...credentials,
    };

    const needsAttestations =
      !analysis.attestations || analysis.attestations.length === 0;
    const [attestations, digests] = await Promise.all([
      needsAttestations
        ? fetchAttestationsFromRegistry({
            ...registryRef,
            platform: parsePlatform(options.platform),
          })
        : undefined,
      options.digests?.manifest
        ? undefined
        : fetchDistributionDigestsFromRegistry({
            ...registryRef,
            platform: parsePlatform(options.platform || analysis.platform),
            expectedConfigDigest: analysis.imageId,
          }),
    ]);
    // Only keep provenance that attests the exact image that was scanned.
    const scannedManifestDigest =
      options.digests?.manifest ?? digests?.manifest;
    return {
      attestations:
        attestations &&
        keepAttestationsForManifest(attestations, scannedManifestDigest),
      digests,
    };
  } catch (error) {
    debug(
      `failed to fetch registry metadata for ${targetImage}: ${getErrorMessage(
        error,
      )}`,
    );
    return {};
  }
}
