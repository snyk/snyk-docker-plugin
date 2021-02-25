import { Dockerfile, DockerfileParser } from "dockerfile-ast";
import * as fs from "fs";
import { EOL } from "os";
import { normalize as normalizePath } from "path";
import { Range } from "vscode-languageserver-types";
import {
  getDockerfileBaseImageName,
  getLayersFromPackages,
  getPackagesFromDockerfile,
  instructionDigest,
} from "./instruction-parser";
import { DockerFileAnalysis } from "./types";

export {
  analyseDockerfile,
  readDockerfileAndAnalyse,
  instructionDigest,
  getPackagesFromDockerfile,
  getDockerfileBaseImageName,
  updateDockerfileBaseImage,
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

/*
 * spike: experimenting with ways to update base image in Dockerfiles
 */
async function updateDockerfileBaseImage(
  contents: string,
  baseImage: string,
): Promise<string | undefined> {
  const dockerfile = DockerfileParser.parse(contents);
  const currentBaseImage = getDockerfileBaseImageName(dockerfile);

  if (currentBaseImage === undefined) {
    return undefined;
  }

  const matchingFromRanges = getFromRanges(dockerfile, currentBaseImage);
  const matchingArgRanges = getArgRanges(dockerfile, currentBaseImage);

  const matchingRanges = ([] as Range[])
    .concat(matchingFromRanges)
    .concat(matchingArgRanges);

  return substituteContent(contents, baseImage, matchingRanges);
}

function getFromRanges(
  dockerfile: Dockerfile,
  currentBaseImage: string,
): Range[] {
  return dockerfile
    .getFROMs()
    .filter((from) => from.getImage() === currentBaseImage)
    .map((from) => from.getImageRange()!);
}

function getArgRanges(
  dockerfile: Dockerfile,
  currentBaseImage: string,
): Range[] {
  return dockerfile
    .getARGs()
    .filter((arg) => arg.getArgumentsContent()?.endsWith(currentBaseImage))
    .map((arg) => {
      const argumentsRange = arg.getArgumentsRange();
      const argumentsContent = arg.getArgumentsContent();
      const argumentsSubRange: Range = {
        start: {
          character:
            argumentsRange!.start.character +
            argumentsContent!.indexOf(currentBaseImage),
          line: argumentsRange!.start.line,
        },
        end: argumentsRange!.end,
      };
      return argumentsSubRange;
    });
}

function substituteContent(
  contents: string,
  replacement: string,
  ranges: Range[],
): string {
  const lines = contents.split(EOL);

  for (const range of ranges) {
    const line = range.start.line;
    const start = range.start.character;
    const end = range.end.character;

    const content = lines[line];
    lines[line] =
      content.substring(0, start) + replacement + content.substring(end);
  }

  return lines.join(EOL);
}
