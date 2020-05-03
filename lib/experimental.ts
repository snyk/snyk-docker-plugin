import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { pullIfNotLocal } from "./analyzer/image-inspector";
import { Docker } from "./docker";
import { DockerFileAnalysis } from "./docker-file";
import { getDockerArchivePath, getImageType } from "./image-type";
import * as staticModule from "./static";
import { ImageType, PluginResponse } from "./types";

export async function experimentalAnalysis(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options: any,
): Promise<PluginResponse> {
  // assume Distroless scanning
  const imageType = getImageType(targetImage);
  switch (imageType) {
    case ImageType.DockerArchive:
      return dockerArchive(targetImage, dockerfileAnalysis);

    case ImageType.Identifier:
      return distroless(targetImage, dockerfileAnalysis, options);

    default:
      throw new Error("Unhandled image type for image " + targetImage);
  }
}

async function dockerArchive(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
): Promise<PluginResponse> {
  const archivePath = getDockerArchivePath(targetImage);
  if (!fs.existsSync(archivePath)) {
    throw new Error(
      "The provided docker archive path does not exist on the filesystem",
    );
  }
  if (!fs.lstatSync(archivePath).isFile()) {
    throw new Error("The provided docker archive path is not a file");
  }
  // The target image becomes the base of the path, e.g. "archive.tar" for "/var/tmp/archive.tar"
  const imageIdentifier = path.basename(archivePath);
  return await getStaticAnalysisResult(
    imageIdentifier,
    archivePath,
    dockerfileAnalysis,
  );
}

// experimental flow expected to be merged with the static analysis when ready
export async function distroless(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options: any,
): Promise<PluginResponse> {
  if (staticModule.isRequestingStaticAnalysis(options)) {
    options.staticAnalysisOptions.distroless = true;
    return staticModule.analyzeStatically(
      targetImage,
      dockerfileAnalysis,
      options,
    );
  }

  await pullIfNotLocal(targetImage);

  const archiveDir = path.join(os.tmpdir(), "snyk-image-archives");
  createTempDirIfMissing(archiveDir);
  // TODO terrible way to convert slashes to anything else
  // so we don't think it's a directory
  const archiveFileName = `${targetImage.replace(/\//g, "__")}.tar`;
  const archiveFullPath = path.join(archiveDir, archiveFileName);

  // assumption #1: the `docker` binary is available locally
  const docker = new Docker(targetImage);
  await docker.save(targetImage, archiveFullPath);
  try {
    return await getStaticAnalysisResult(
      targetImage,
      archiveFullPath,
      dockerfileAnalysis,
    );
  } finally {
    fs.unlinkSync(archiveFullPath);
  }
}

async function getStaticAnalysisResult(
  targetImage: string,
  archivePath: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
): Promise<PluginResponse> {
  const scanningOptions = {
    staticAnalysisOptions: {
      imagePath: archivePath,
      imageType: ImageType.DockerArchive,
      distroless: true,
    },
  };

  return await staticModule.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    scanningOptions,
  );
}

function createTempDirIfMissing(archiveDir: string): void {
  try {
    fs.mkdirSync(archiveDir);
  } catch (err) {
    if (err.code !== "EEXIST") {
      throw err;
    }
  }
}
