import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { pullIfNotLocal } from "./analyzer/image-inspector";
import { Docker } from "./docker";
import { getDockerArchivePath, getImageTransport } from "./image-transport";
import * as staticModule from "./static";
import {
  ImageTransport,
  ImageType,
  PluginResponse,
  StaticAnalysisOptions,
} from "./types";

export async function experimentalAnalysis(
  targetImage: string,
  options: any,
): Promise<PluginResponse> {
  // assume Distroless scanning
  const imageTransport = getImageTransport(targetImage);
  switch (imageTransport) {
    case ImageTransport.DockerArchive:
      // TODO: maybe all the steps in this case can be wrapped in a function
      const imagePath = getDockerArchivePath(targetImage);
      // TODO: validate the file in "imagePath" exists
      const staticAnalysisOptions: StaticAnalysisOptions = {
        imagePath,
        imageType: ImageType.DockerArchive,
        distroless: true,
      };
      return staticModule.analyzeStatically(targetImage, {
        staticAnalysisOptions,
      });

    case ImageTransport.ContainerRegistry:
      return distroless(targetImage, options);

    default:
      throw new Error("Unhandled image transport for image " + targetImage);
  }
}

// experimental flow expected to be merged with the static analysis when ready
export async function distroless(
  targetImage: string,
  options: any,
): Promise<PluginResponse> {
  if (staticModule.isRequestingStaticAnalysis(options)) {
    options.staticAnalysisOptions.distroless = true;
    return staticModule.analyzeStatically(targetImage, options);
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
    const scanningOptions = {
      staticAnalysisOptions: {
        imagePath: archiveFullPath,
        imageType: ImageType.DockerArchive,
        distroless: true,
      },
    };

    return await staticModule.analyzeStatically(targetImage, scanningOptions);
  } finally {
    fs.unlinkSync(archiveFullPath);
  }
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
