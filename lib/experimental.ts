import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { Docker } from "./docker";
import * as staticModule from "./static";
import { ImageType, PluginResponse } from "./types";

export async function experimentalAnalysis(
  targetImage: string,
): Promise<PluginResponse> {
  // assume Distroless scanning
  return distroless(targetImage);
}

// experimental flow expected to be merged with the static analysis when ready
export async function distroless(targetImage: string): Promise<PluginResponse> {
  const archiveDir = path.join(os.tmpdir(), "snyk-image-archives");
  createTempDirIfMissing(archiveDir);
  // TODO terrible way to convert slashes to anything else
  // so we don't think it's a directory
  const archiveFileName = `${targetImage.replace(/\//g, "__")}.tar`;
  const archiveFullPath = path.join(archiveDir, archiveFileName);

  // assumption #2: the `docker` binary is available locally
  const docker = new Docker(targetImage);
  // assumption #1: the image is present in the local Docker daemon
  await docker.save(targetImage, archiveFullPath);
  try {
    const scanningOptions = {
      staticAnalysisOptions: {
        imagePath: archiveFullPath,
        imageType: ImageType.DockerArchive,
        // TODO only for RPM, may be removed once we get rid of bdb dep
        tmpDirPath: "",
        distroless: true,
      },
    };

    return staticModule.analyzeStatically(targetImage, scanningOptions);
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
