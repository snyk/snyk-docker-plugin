import * as fs from "fs";
import * as path from "path";

import { getImageArchive } from "./analyzer/image-inspector";
import { readDockerfileAndAnalyse } from "./dockerfile";
import { DockerFileAnalysis } from "./dockerfile/types";
import { extractImageContent } from "./extractor";
import { ImageName } from "./extractor/image";
import { ExtractAction, ExtractionResult } from "./extractor/types";
import { fullImageSavePath } from "./image-save-path";
import { getArchivePath, getImageType } from "./image-type";
import { isStrictNumber, isTrue } from "./option-utils";
import * as staticModule from "./static";
import { ImageType, PluginOptions, PluginResponse } from "./types";
import { isValidDockerImageReference } from "./utils";

// Registry credentials may also be provided by env vars. When both are set, flags take precedence.
export function mergeEnvVarsIntoCredentials(
  options: Partial<PluginOptions>,
): void {
  options.username = options.username || process.env.SNYK_REGISTRY_USERNAME;
  options.password = options.password || process.env.SNYK_REGISTRY_PASSWORD;
}

async function getAnalysisParameters(
  options?: Partial<PluginOptions>,
): Promise<{
  targetImage: string;
  imageType: ImageType;
  dockerfileAnalysis: DockerFileAnalysis | undefined;
  options: Partial<PluginOptions>;
}> {
  if (!options) {
    throw new Error("No plugin options provided");
  }

  mergeEnvVarsIntoCredentials(options);

  if (!options.path) {
    throw new Error("No image identifier or path provided");
  }

  const nestedJarsDepth = [
    options["nested-jars-depth"],
    options["shaded-jars-depth"],
  ].find((val) => val !== "" && val != null);
  if (isStrictNumber(nestedJarsDepth) && isTrue(options["exclude-app-vulns"])) {
    throw new Error(
      "To use --nested-jars-depth, you must not use --exclude-app-vulns",
    );
  }

  if (
    (!isStrictNumber(nestedJarsDepth) &&
      typeof nestedJarsDepth !== "undefined") ||
    Number(nestedJarsDepth) < 0
  ) {
    throw new Error(
      "--nested-jars-depth accepts only numbers bigger than or equal to 0",
    );
  }

  // TODO temporary solution to avoid double results for PHP if exists in `globsToFind`
  if (options.globsToFind) {
    options.globsToFind.include = options.globsToFind.include.filter(
      (glob) => !glob.includes("composer"),
    );
  }

  const targetImage = appendLatestTagIfMissing(options.path);

  const dockerfilePath = options.file;
  const dockerfileAnalysis = await readDockerfileAndAnalyse(dockerfilePath);

  const imageType = getImageType(targetImage);
  return {
    targetImage,
    imageType,
    dockerfileAnalysis,
    options,
  };
}

export async function scan(
  options?: Partial<PluginOptions>,
): Promise<PluginResponse> {
  const {
    targetImage,
    imageType,
    dockerfileAnalysis,
    options: updatedOptions,
  } = await getAnalysisParameters(options);
  switch (imageType) {
    case ImageType.DockerArchive:
    case ImageType.OciArchive:
    case ImageType.KanikoArchive:
    case ImageType.UnspecifiedArchiveType:
      return localArchiveAnalysis(
        targetImage,
        imageType,
        dockerfileAnalysis,
        updatedOptions,
      );
    case ImageType.Identifier:
      return imageIdentifierAnalysis(
        targetImage,
        imageType,
        dockerfileAnalysis,
        updatedOptions,
      );

    default:
      throw new Error("Unhandled image type for image " + targetImage);
  }
}

function getAndValidateArchivePath(targetImage: string) {
  const archivePath = getArchivePath(targetImage);
  if (!fs.existsSync(archivePath)) {
    throw new Error(
      "The provided archive path does not exist on the filesystem",
    );
  }
  if (!fs.lstatSync(archivePath).isFile()) {
    throw new Error("The provided archive path is not a file");
  }

  return archivePath;
}

async function localArchiveAnalysis(
  targetImage: string,
  imageType: ImageType,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options: Partial<PluginOptions>,
): Promise<PluginResponse> {
  const globToFind = {
    include: options.globsToFind?.include || [],
    exclude: options.globsToFind?.exclude || [],
  };

  const archivePath = getAndValidateArchivePath(targetImage);
  const imageIdentifier =
    options.imageNameAndTag ||
    // The target image becomes the base of the path, e.g. "archive.tar" for "/var/tmp/archive.tar"
    path.basename(archivePath);

  let imageName: ImageName | undefined;
  if (
    (options.digests?.manifest || options.digests?.index) &&
    options.imageNameAndTag
  ) {
    imageName = new ImageName(options.imageNameAndTag, {
      manifest: options.digests?.manifest,
      index: options.digests?.index,
    });
  }

  return await staticModule.analyzeStatically(
    imageIdentifier,
    dockerfileAnalysis,
    imageType,
    archivePath,
    globToFind,
    options,
    imageName,
  );
}

async function imageIdentifierAnalysis(
  targetImage: string,
  imageType: ImageType,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options: Partial<PluginOptions>,
): Promise<PluginResponse> {
  // Validate Docker image reference format to catch malformed references early. We implement initial validation here
  // in lieu of simply sending to the docker daemon since some invalid references can result in unknown or invalid API
  // paths to the Docker daemon, sometimes producing confusing error results (like redirects) instead of the not found response.
  if (!isValidDockerImageReference(targetImage)) {
    throw new Error(`invalid image reference format: ${targetImage}`);
  }

  const globToFind = {
    include: options.globsToFind?.include || [],
    exclude: options.globsToFind?.exclude || [],
  };

  const imageSavePath = fullImageSavePath(options.imageSavePath);
  const archiveResult = await getImageArchive(
    targetImage,
    imageSavePath,
    options.username,
    options.password,
    options.platform,
  );

  const imagePath = archiveResult.path;
  const imageName = archiveResult.imageName;
  try {
    return await staticModule.analyzeStatically(
      targetImage,
      dockerfileAnalysis,
      imageType,
      imagePath,
      globToFind,
      options,
      imageName,
    );
  } finally {
    archiveResult.removeArchive();
  }
}

export function appendLatestTagIfMissing(targetImage: string): string {
  if (
    getImageType(targetImage) === ImageType.Identifier &&
    !targetImage.includes(":")
  ) {
    return `${targetImage}:latest`;
  }
  return targetImage;
}

export async function extractContent(
  extractActions: ExtractAction[],
  options?: Partial<PluginOptions>,
): Promise<ExtractionResult> {
  const {
    targetImage,
    imageType,
    options: updatedOptions,
  } = await getAnalysisParameters(options);

  const { username, password, platform, imageSavePath } = updatedOptions;
  let imagePath: string;
  switch (imageType) {
    case ImageType.DockerArchive:
    case ImageType.OciArchive:
      imagePath = getAndValidateArchivePath(targetImage);
      break;
    case ImageType.Identifier:
      const imageSavePathFull = fullImageSavePath(imageSavePath);
      const archiveResult = await getImageArchive(
        targetImage,
        imageSavePathFull,
        username,
        password,
        platform,
      );
      imagePath = archiveResult.path;
      break;
    default:
      throw new Error("Unhandled image type for image " + targetImage);
  }

  return extractImageContent(
    imageType,
    imagePath,
    extractActions,
    updatedOptions,
  );
}
