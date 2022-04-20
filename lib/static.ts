import { DepGraph } from "@snyk/dep-graph";
import * as analyzer from "./analyzer";
import {
  AnalyzedPackage,
  Binary,
  OSRelease,
  StaticAnalysis,
} from "./analyzer/types";
import { buildGraph } from "./dependency-graph";
import { DockerFileAnalysis, DockerFilePackages } from "./dockerfile/types";
import { isTrue } from "./option-utils";
import { parseAnalysisResults } from "./parser";
import { buildResponse } from "./response-builder";
import { ImageType, PluginOptions, PluginResponse } from "./types";

export async function analyzeStatically(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  imagePath: string,
  globsToFind: { include: string[]; exclude: string[] },
  options: Partial<PluginOptions>,
): Promise<PluginResponse> {
  const staticAnalysis = await analyzer.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    imageType,
    imagePath,
    globsToFind,
    options,
  );

  const parsedAnalysisResult: {
    imageId: string;
    platform: string | undefined;
    targetOS: OSRelease;
    type: any;
    depInfosList: AnalyzedPackage[] | Binary[];
    imageLayers: string[];
  } = parseAnalysisResults(targetImage, staticAnalysis);

  const depInfosList = parsedAnalysisResult.depInfosList as AnalyzedPackage[];
  const dockerfilePackages = getFilteredDockerfilePackages(
    dockerfileAnalysis,
    depInfosList,
    isTrue(options["exclude-base-image-vulns"]),
  );

  const depGraph = await buildGraph(
    targetImage,
    parsedAnalysisResult.targetOS,
    parsedAnalysisResult.type,
    depInfosList,
    dockerfilePackages,
  );

  const analysis: StaticAnalysis & {
    depGraph: DepGraph;
    depInfosList: AnalyzedPackage[];
    packageManager: string;
    targetOS: OSRelease;
  } = {
    ...staticAnalysis,
    depGraph,
    depInfosList: depInfosList,
    imageId: parsedAnalysisResult.imageId,
    imageLayers: parsedAnalysisResult.imageLayers,
    packageManager: parsedAnalysisResult.type,
    targetOS: parsedAnalysisResult.targetOS,
  };
  return buildResponse(analysis, dockerfileAnalysis);
}

function getFilteredDockerfilePackages(
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  depInfosList: AnalyzedPackage[],
  excludeBaseImageVulns: boolean,
): DockerFilePackages | undefined {
  let dockerfilePackages: DockerFilePackages;
  let filteredDockerfilePackages: DockerFilePackages;

  if (dockerfileAnalysis) {
    dockerfilePackages = getUserInstructionDeps(
      dockerfileAnalysis.dockerfilePackages,
      depInfosList,
    );

    if (excludeBaseImageDeps && dockerfilePackages) {
      filteredDockerfilePackages = excludeBaseImageDeps(
        depInfosList,
        dockerfilePackages,
        excludeBaseImageVulns,
      );
      return filteredDockerfilePackages;
    }
    return dockerfilePackages;
  }
  return undefined;
}

// Iterate over the dependencies list; if one is introduced by the dockerfile,
// flatten its dependencies and append them to the list of dockerfile
// packages. This gives us a reference of all transitive deps installed via
// the dockerfile, and the instruction that installed it.
export function getUserInstructionDeps(
  dockerfilePackages: DockerFilePackages,
  extractedPackages: AnalyzedPackage[],
): DockerFilePackages {
  for (const extractedPackage of extractedPackages) {
    const dockerfilePackage = dockerfilePackages[extractedPackage.Name];

    if (dockerfilePackage) {
      for (const dep in extractedPackage.Deps) {
        if (extractedPackage.Deps.hasOwnProperty(dep)) {
          dockerfilePackages[dep] = { ...dockerfilePackage };
        }
      }
    }
  }

  return dockerfilePackages;
}

// Skip processing if option disabled or dockerfilePkgs is undefined. We
// can't exclude anything in that case, because we can't tell which deps are
// from dockerfile and which from base image.
function excludeBaseImageDeps(
  deps: AnalyzedPackage[],
  dockerfilePkgs: DockerFilePackages | undefined,
  excludeBaseImageVulns: boolean,
) {
  if (!excludeBaseImageVulns || !dockerfilePkgs) {
    return deps;
  }

  return extractDockerfileDeps(deps, dockerfilePkgs);
}

function extractDockerfileDeps(
  allDeps: AnalyzedPackage[],
  dockerfilePkgs: DockerFilePackages,
) {
  return Object.keys(allDeps)
    .filter((depName) => dockerfilePkgs[depName])
    .reduce((extractedDeps, depName) => {
      extractedDeps[depName] = allDeps[depName];
      return extractedDeps;
    }, {});
}
