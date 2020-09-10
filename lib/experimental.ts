import * as fs from "fs";
import * as path from "path";
import * as tmp from "tmp";
import { v4 as uuidv4 } from "uuid";

import { getImageArchive } from "./analyzer/image-inspector";
import { DockerFileAnalysis } from "./docker-file";
import { getArchivePath, getImageType } from "./image-type";
import * as staticModule from "./static";
import { ImageType, ScanOptions, ScanResult } from "./types";

export async function experimentalAnalysis(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options?: Partial<ScanOptions>,
): Promise<ScanResult[]> {
  // assume Distroless scanning
  const imageType = getImageType(targetImage);
  switch (imageType) {
    case ImageType.DockerArchive:
    case ImageType.OciArchive:
      return localArchive(targetImage, imageType, dockerfileAnalysis, options);
    case ImageType.Identifier:
      return distroless(targetImage, dockerfileAnalysis, options);

    default:
      throw new Error("Unhandled image type for image " + targetImage);
  }
}

async function localArchive(
  targetImage: string,
  imageType: ImageType,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options?: Partial<ScanOptions>,
): Promise<ScanResult[]> {
  const archivePath = getArchivePath(targetImage);
  if (!fs.existsSync(archivePath)) {
    throw new Error(
      "The provided archive path does not exist on the filesystem",
    );
  }
  if (!fs.lstatSync(archivePath).isFile()) {
    throw new Error("The provided archive path is not a file");
  }
  // The target image becomes the base of the path, e.g. "archive.tar" for "/var/tmp/archive.tar"
  const imageIdentifier = path.basename(archivePath);
  return await getStaticAnalysisResult(
    imageIdentifier,
    archivePath,
    dockerfileAnalysis,
    imageType,
    options?.["app-vulns"] || false,
  );
}

// experimental flow expected to be merged with the static analysis when ready
export async function distroless(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options?: Partial<ScanOptions>,
): Promise<ScanResult[]> {
  if (staticModule.isRequestingStaticAnalysis(options)) {
    if (!options) {
      options = { experimental: true };
    }
    return staticModule.analyzeStatically(
      targetImage,
      dockerfileAnalysis,
      options,
    );
  }

  const imageSavePath = fullImageSavePath(options?.imageSavePath);
  const archiveResult = await getImageArchive(
    targetImage,
    imageSavePath,
    options?.username,
    options?.password,
    options?.platform,
  );
  try {
    return await getStaticAnalysisResult(
      targetImage,
      archiveResult.path,
      dockerfileAnalysis,
      ImageType.DockerArchive,
      options?.["app-vulns"] || false,
    );
  } finally {
    archiveResult.removeArchive();
  }
}

async function getStaticAnalysisResult(
  targetImage: string,
  archivePath: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  appScan: boolean,
): Promise<ScanResult[]> {
  const scanningOptions: Partial<ScanOptions> = {
    imagePath: archivePath,
    imageType,
    experimental: true,
    appScan,
  };

  return await staticModule.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    scanningOptions,
  );
}

export function fullImageSavePath(imageSavePath: string | undefined): string {
  let imagePath = tmp.dirSync().name;
  if (imageSavePath) {
    imagePath = path.normalize(imageSavePath);
  }

  return path.join(imagePath, uuidv4());
}
