import { DockerfileParser } from "dockerfile-ast";
import * as fs from "fs";
import { normalize as normalizePath } from "path";
import {
  getDockerfileBaseImageName,
  getLayersFromPackages,
  getPackagesFromDockerfile,
  instructionDigest,
} from "./instruction-parser";
import { updateDockerfileBaseImageName } from "./instruction-updater";
import {
  DockerFileAnalysis,
  DockerFileAnalysisErrorCode,
  DockerFileAnalysisError,
} from "./types";

export {
  analyseDockerfile,
  readDockerfileAndAnalyse,
  instructionDigest,
  getPackagesFromDockerfile,
  getDockerfileBaseImageName,
  updateDockerfileBaseImageName,
  DockerFileAnalysis,
};

async function readDockerfileAndAnalyse(
  dockerfilePath?: string,
): Promise<DockerFileAnalysis | undefined> {
  if (!dockerfilePath) {
    return undefined;
  }

  const contents = await readFile(normalizePath(dockerfilePath));
  return analyseDockerfile(contents);
}

async function analyseDockerfile(
  contents: string,
): Promise<DockerFileAnalysis> {
  const dockerfile = DockerfileParser.parse(contents);
  const baseImage = getDockerfileBaseImageName(dockerfile);
  const dockerfilePackages = getPackagesFromDockerfile(dockerfile);
  const dockerfileLayers = getLayersFromPackages(dockerfilePackages);

  let error: DockerFileAnalysisError | undefined = undefined;
  if (dockerfile.getFROMs().length === 0) {
    error = {
      code: DockerFileAnalysisErrorCode.BASE_IMAGE_NAME_NOT_FOUND,
    };
  } else if (!baseImage) {
    error = {
      code: DockerFileAnalysisErrorCode.BASE_IMAGE_NON_RESOLVABLE,
    };
  }

  return {
    baseImage,
    dockerfilePackages,
    dockerfileLayers,
    error,
  };
}

async function readFile(path: string) {
  return new Promise((resolve, reject) => {
    fs.readFile(path, "utf8", (err, data) => {
      return err ? reject(err) : resolve(data);
    });
  }) as Promise<string>;
}
