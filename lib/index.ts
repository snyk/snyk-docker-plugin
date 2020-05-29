import * as Debug from "debug";
import * as path from "path";

import * as analyzer from "./analyzer";
import { buildTree } from "./dependency-tree";
import { Docker, DockerOptions } from "./docker";
import * as dockerFile from "./docker-file";
import { tryGetAnalysisError } from "./errors";
import { experimentalAnalysis } from "./experimental";
import { getRuntime } from "./inputs/runtime/docker";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import * as staticUtil from "./static";
import {
  DepTree,
  ManifestFile,
  PluginResponse,
  ScannedProjectExtended,
  ScannedProjectManifestFiles,
  ScanType,
} from "./types";

export {
  inspect,
  dockerFile,
  PluginResponse,
  ScannedProjectExtended,
  ScanType,
  ScannedProjectManifestFiles,
  DepTree,
};

const MAX_MANIFEST_FILES = 5;
const debug = Debug("snyk");

async function inspect(
  root: string,
  targetFile?: string,
  options?: any,
): Promise<PluginResponse> {
  const targetImage = root;

  const dockerfileAnalysis = await dockerFile.readDockerfileAndAnalyse(
    targetFile,
  );

  if (options && options.experimental) {
    return await experimentalAnalysis(targetImage, dockerfileAnalysis, options);
  }

  if (staticUtil.isRequestingStaticAnalysis(options)) {
    return await staticUtil.analyzeStatically(
      targetImage,
      dockerfileAnalysis,
      options,
    );
  }

  return await analyzeDynamically(
    targetImage,
    dockerfileAnalysis,
    getDynamicAnalysisOptions(options),
  );
}

async function analyzeDynamically(
  targetImage: string,
  dockerfileAnalysis: dockerFile.DockerFileAnalysis | undefined,
  analysisOptions: any,
): Promise<PluginResponse> {
  const [runtime, dependencies, manifestFiles] = await Promise.all([
    getRuntime(analysisOptions),
    getDependencies(targetImage, dockerfileAnalysis, analysisOptions),
    getManifestFiles(targetImage, analysisOptions),
  ]);

  return buildResponse(
    runtime,
    dependencies,
    dockerfileAnalysis,
    manifestFiles!, // bug in typescript wrongly adds `undefined`
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

async function getManifestFiles(
  targetImage: string,
  options?: any,
): Promise<ManifestFile[]> {
  if (!options.manifestGlobs) {
    return [];
  }

  let excludeGlobs: string[] = [];
  if (options.manifestExcludeGlobs) {
    excludeGlobs = options.manifestExcludeGlobs as string[];
  }

  const globs = options.manifestGlobs as string[];
  const docker = new Docker(targetImage, options);

  let files = await docker.findGlobs(globs, excludeGlobs);

  // Limit the number of manifest files which we return
  // to avoid overwhelming the docker daemon with cat requests

  if (files.length > MAX_MANIFEST_FILES) {
    debug(
      `Found ${files.length} manifest files in total. Only keeping the first ${MAX_MANIFEST_FILES}.`,
    );
    files = files.slice(0, MAX_MANIFEST_FILES);
  }

  const contents = await Promise.all(files.map((f) => docker.catSafe(f)));

  return files
    .map((g, i) => {
      return {
        name: path.basename(g),
        path: path.dirname(g),
        contents: Buffer.from(contents[i].stdout),
      };
    })
    .filter((i) => i.contents.length > 0);
}
