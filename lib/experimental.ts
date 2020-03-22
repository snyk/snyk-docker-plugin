import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { pullIfNotLocal } from "./analyzer/image-inspector";
import { Docker } from "./docker";
import * as staticModule from "./static";
import { ImageType, PluginResponse } from "./types";

export async function experimentalAnalysis(
  targetImage: string,
  options: any,
): Promise<PluginResponse> {
  // assume Distroless scanning
  return distroless(targetImage, options);
}

// experimental flow expected to be merged with the static analysis when ready
export async function distroless(
  targetImage: string,
  options: any,
): Promise<PluginResponse> {
  if (staticModule.isRequestingStaticAnalysis(options)) {
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
