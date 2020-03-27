import * as path from "path";
import * as analyzer from "./analyzer";
import { buildTree } from "./dependency-tree";
import { Docker, DockerOptions, Globs } from "./docker";
import * as dockerFile from "./docker-file";
import { tryGetAnalysisError } from "./errors";
import { experimentalAnalysis } from "./experimental";
import { getRuntime } from "./inputs/runtime/docker";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import * as staticUtil from "./static";
import { FindFilesResult, ManifestFile, PluginResponse } from "./types";

export { inspect, dockerFile };

const MAX_MANIFEST_FILES = 5;

function inspect(
  root: string,
  targetFile?: string,
  options?: any,
): Promise<PluginResponse> {
  const targetImage = root;

  if (options && options.experimental) {
    return experimentalAnalysis(targetImage, options);
  }

  if (staticUtil.isRequestingStaticAnalysis(options)) {
    return staticUtil.analyzeStatically(targetImage, options);
  }

  return dockerFile
    .readDockerfileAndAnalyse(targetFile)
    .then((dockerfileAnalysis) => {
      return analyzeDynamically(
        targetImage,
        dockerfileAnalysis,
        getDynamicAnalysisOptions(options),
      );
    });
}

async function analyzeDynamically(
  targetImage: string,
  dockerfileAnalysis: dockerFile.DockerFileAnalysis | undefined,
  analysisOptions: any,
): Promise<PluginResponse> {
  const [runtime, dependencies, findFilesResult] = await Promise.all([
    getRuntime(analysisOptions),
    getDependencies(targetImage, dockerfileAnalysis, analysisOptions),
    getFiles(targetImage, analysisOptions),
  ]);

  const { manifestFiles, binaryFiles } = findFilesResult as FindFilesResult;

  return buildResponse(
    runtime,
    dependencies,
    dockerfileAnalysis,
    manifestFiles,
    binaryFiles,
    analysisOptions,
  );
}

// TODO: return type should be "DynamicAnalysisOptions" or something that extends DockerOptions
function getDynamicAnalysisOptions(options?: any): any {
  return options
    ? {
        host: options.host,
        tlsverify: options.tlsverify,
        tlscert: options.tlscert,
        tlscacert: options.tlscacert,
        tlskey: options.tlskey,
        manifestGlobs: options.manifestGlobs,
        manifestExcludeGlobs: options.manifestExcludeGlobs,
      }
    : {};
}

async function getDependencies(
  targetImage: string,
  dockerfileAnalysis?: dockerFile.DockerFileAnalysis,
  options?: DockerOptions,
) {
  try {
    const output = await analyzer.analyzeDynamically(
      targetImage,
      dockerfileAnalysis,
      options,
    );
    const result = parseAnalysisResults(targetImage, output);
    const pkg = buildTree(
      targetImage,
      result.type,
      result.depInfosList,
      result.targetOS,
    );

    return {
      package: pkg,
      packageManager: result.type,
      imageId: result.imageId,
      binaries: result.binaries,
      imageLayers: result.imageLayers,
    };
  } catch (error) {
    const analysisError = tryGetAnalysisError(error, targetImage);
    throw analysisError;
  }
}

async function getFiles(
  targetImage: string,
  options?: any,
): Promise<FindFilesResult> {
  if (!options.manifestGlobs && !options.binariesGlobs) {
    return {
      manifestFiles: [],
      binaryFiles: [],
    };
  }

  let excludeGlobs: string[] = [];
  if (options.manifestExcludeGlobs) {
    excludeGlobs = options.manifestExcludeGlobs as string[];
  }

  const docker = new Docker(targetImage, options);

  const globs: Globs = {
    manifestGlobs: [],
    binaryGlobs: [],
  };

  if (options.manifestGlobs) {
    globs.manifestGlobs = options.manifestGlobs as string[];
  }

  if (options.binariesGlobs) {
    globs.binaryGlobs = options.binariesGlobs as string[];
  }

  const { manifestFiles, binaryFiles } = await docker.findGlobs(
    globs,
    excludeGlobs,
  );

  const [manifestFilesResult, binaryFilesResult] = await Promise.all([
    handleManifestFiles(docker, manifestFiles),
    docker.calcHashOfBinaryFiles(binaryFiles, options),
  ]);

  return {
    manifestFiles: manifestFilesResult,
    binaryFiles: binaryFilesResult,
  };
}

async function handleManifestFiles(
  docker: Docker,
  files: string[],
): Promise<ManifestFile[]> {
  // Limit the number of manifest files which we return
  // to avoid overwhelming the docker daemon with cat requests

  if (files.length > MAX_MANIFEST_FILES) {
    files = files.slice(0, MAX_MANIFEST_FILES);
  }

  const contents = await Promise.all(files.map((f) => docker.catSafe(f)));

  return files
    .map((g, i) => {
      return {
        name: path.basename(g),
        path: path.dirname(g),
        contents: Buffer.from(contents[i].stdout).toString("base64"),
      };
    })
    .filter((i) => i.contents !== "");
}
