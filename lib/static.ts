import * as analyzer from "./analyzer";
import { buildTree } from "./dependency-tree";
import { tryGetAnalysisError } from "./errors";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import { HASH_ALGORITHM } from "./stream-utils";
import { BinaryFileData, PluginResponse, StaticAnalysisOptions } from "./types";

export async function analyzeStatically(
  targetImage: string,
  options: any,
): Promise<PluginResponse> {
  const staticAnalysisOptions = getStaticAnalysisOptions(options);

  // Relevant only if using a Docker runtime. Optional, but we may consider what to put here
  // to present to the user in Snyk UI.
  const runtime = undefined;
  // Both the analysis and the manifest files are relevant if inspecting a Dockerfile.
  // This is not the case for static scanning.
  const dockerfileAnalysis = undefined;
  const manifestFiles = [];

  try {
    const staticAnalysis = await analyzer.analyzeStatically(
      targetImage,
      staticAnalysisOptions,
    );

    const parsedAnalysisResult = parseAnalysisResults(
      targetImage,
      staticAnalysis,
    );

    const dependenciesTree = await buildTree(
      targetImage,
      parsedAnalysisResult.type,
      parsedAnalysisResult.depInfosList,
      parsedAnalysisResult.targetOS,
    );

    const analysis = {
      package: dependenciesTree,
      packageManager: parsedAnalysisResult.type,
      imageId: parsedAnalysisResult.imageId,
      binaries: parsedAnalysisResult.binaries,
      imageLayers: parsedAnalysisResult.imageLayers,
    };

    const binHashFiles: BinaryFileData[] = [];

    // hacking our way through types for backwards compatibility
    const response: PluginResponse = {
      ...buildResponse(
        runtime,
        analysis,
        dockerfileAnalysis,
        manifestFiles,
        binHashFiles,
        staticAnalysisOptions,
      ),
      binaryFiles: [],
    };

    // TODO: name/path are missing from static workflow
    for (const hash of staticAnalysis.binaries) {
      response.binaryFiles.push({
        name: "",
        path: "",
        hashType: HASH_ALGORITHM,
        hash,
      });
    }

    return response;
  } catch (error) {
    const analysisError = tryGetAnalysisError(error, targetImage);
    throw analysisError;
  }
}

export function isRequestingStaticAnalysis(options?: any): boolean {
  return options && options.staticAnalysisOptions;
}

function getStaticAnalysisOptions(options: any): StaticAnalysisOptions {
  if (
    !options ||
    !options.staticAnalysisOptions ||
    !options.staticAnalysisOptions.imagePath ||
    options.staticAnalysisOptions.imageType === undefined
  ) {
    throw new Error("Missing required parameters for static analysis");
  }

  return {
    imagePath: options.staticAnalysisOptions.imagePath,
    imageType: options.staticAnalysisOptions.imageType,
    tmpDirPath: options.staticAnalysisOptions.tmpDirPath,
    distroless: options.staticAnalysisOptions.distroless,
  };
}
