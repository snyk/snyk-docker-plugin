import { DockerfileParser } from "dockerfile-ast";
import * as fs from "fs";
import { normalize as normalizePath } from "path";
import {
  getDockerfileBaseImageName,
  getDockerfileLayers,
  getPackagesFromRunInstructions,
  instructionDigest,
} from "./instruction-parser";
import { DockerFileAnalysis } from "./types";

export {
  analyseDockerfile,
  readDockerfileAndAnalyse,
  instructionDigest,
  getPackagesFromRunInstructions,
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
  const dockerfilePackages = getPackagesFromRunInstructions(dockerfile);
  const dockerfileLayers = getDockerfileLayers(dockerfilePackages);
  return {
    baseImage,
    dockerfilePackages,
    dockerfileLayers,
  };
}

async function readFile(path: string) {
  return new Promise((resolve, reject) => {
    fs.readFile(path, "utf8", (err, data) => {
      return err ? reject(err) : resolve(data);
    });
  }) as Promise<string>;
}
