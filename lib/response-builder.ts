import { DepGraph } from "@snyk/dep-graph";
import { AnalyzedPackage, OSRelease, StaticAnalysis } from "./analyzer/types";
import * as facts from "./facts";
// Module that provides functions to collect and build response after all
// analyses' are done.
import { DockerFileAnalysis } from "./dockerfile/types";
import * as types from "./types";
import { getUserInstructionDeps } from "./static";

export { buildResponse };

async function buildResponse(
  depsAnalysis: StaticAnalysis & {
    depGraph: DepGraph;
    depInfosList: AnalyzedPackage[];
    packageManager: string;
    targetOS: OSRelease;
  },
  dockerfileAnalysis: DockerFileAnalysis | undefined,
): Promise<types.PluginResponse> {
  const additionalFacts: types.Fact[] = [];

  const hashes = depsAnalysis.binaries;
  if (hashes && hashes.length > 0) {
    const keyBinariesHashesFact: facts.KeyBinariesHashesFact = {
      type: "keyBinariesHashes",
      data: hashes,
    };
    additionalFacts.push(keyBinariesHashesFact);
  }

  if (dockerfileAnalysis !== undefined) {
    const dockerfileAnalysisFact: facts.DockerfileAnalysisFact = {
      type: "dockerfileAnalysis",
      data: dockerfileAnalysis,
    };
    additionalFacts.push(dockerfileAnalysisFact);
  }

  if (depsAnalysis.imageId) {
    const imageIdFact: facts.ImageIdFact = {
      type: "imageId",
      data: depsAnalysis.imageId,
    };
    additionalFacts.push(imageIdFact);
  }

  if (depsAnalysis.imageLayers && depsAnalysis.imageLayers.length > 0) {
    const imageLayersFact: facts.ImageLayersFact = {
      type: "imageLayers",
      data: depsAnalysis.imageLayers,
    };
    additionalFacts.push(imageLayersFact);
  }

  if (depsAnalysis.imageLabels) {
    const imageLabels: facts.ImageLabels = {
      type: "imageLabels",
      data: depsAnalysis.imageLabels,
    };
    additionalFacts.push(imageLabels);
  }

  if (depsAnalysis.imageCreationTime) {
    const imageCreationTimeFact: facts.ImageCreationTimeFact = {
      type: "imageCreationTime",
      data: depsAnalysis.imageCreationTime,
    };
    additionalFacts.push(imageCreationTimeFact);
  }

  if (
    depsAnalysis.rootFsLayers &&
    Array.isArray(depsAnalysis.rootFsLayers) &&
    depsAnalysis.rootFsLayers.length > 0
  ) {
    const rootFsFact: facts.RootFsFact = {
      type: "rootFs",
      data: depsAnalysis.rootFsLayers,
    };
    additionalFacts.push(rootFsFact);
  }

  if (depsAnalysis.targetOS.prettyName) {
    const imageOsReleasePrettyNameFact: facts.ImageOsReleasePrettyNameFact = {
      type: "imageOsReleasePrettyName",
      data: depsAnalysis.targetOS.prettyName,
    };
    additionalFacts.push(imageOsReleasePrettyNameFact);
  }

  const manifestFiles =
    depsAnalysis.manifestFiles.length > 0
      ? depsAnalysis.manifestFiles
      : undefined;
  if (manifestFiles) {
    const imageManifestFilesFact: facts.ImageManifestFilesFact = {
      type: "imageManifestFiles",
      data: manifestFiles,
    };
    additionalFacts.push(imageManifestFilesFact);
  }

  const autoDetectedPackages =
    depsAnalysis.autoDetectedUserInstructions?.dockerfilePackages;
  const autoDetectedLayers =
    depsAnalysis.autoDetectedUserInstructions?.dockerfileLayers;
  if (
    autoDetectedPackages &&
    Object.keys(autoDetectedPackages).length > 0 &&
    autoDetectedLayers &&
    Object.keys(autoDetectedLayers).length > 0
  ) {
    const autoDetectedPackagesWithChildren = getUserInstructionDeps(
      autoDetectedPackages,
      depsAnalysis.depInfosList,
    );

    const autoDetectedUserInstructionsFact: facts.AutoDetectedUserInstructionsFact = {
      type: "autoDetectedUserInstructions",
      data: {
        dockerfileLayers: autoDetectedLayers,
        dockerfilePackages: autoDetectedPackagesWithChildren!,
      },
    };
    additionalFacts.push(autoDetectedUserInstructionsFact);
  }

  const applicationDependenciesScanResults: types.ScanResult[] = (
    depsAnalysis.applicationDependenciesScanResults || []
  ).map((appDepsScanResult) => {
    if (depsAnalysis.imageId) {
      const imageIdFact: facts.ImageIdFact = {
        type: "imageId",
        data: depsAnalysis.imageId,
      };
      appDepsScanResult.facts.push(imageIdFact);
    }

    return {
      ...appDepsScanResult,
      target: {
        image: depsAnalysis.depGraph.rootPkg.name,
      },
    };
  });

  const args =
    depsAnalysis.platform !== undefined
      ? { platform: depsAnalysis.platform }
      : undefined;

  const depGraphFact: facts.DepGraphFact = {
    type: "depGraph",
    data: depsAnalysis.depGraph,
  };
  const scanResults: types.ScanResult[] = [
    {
      facts: [depGraphFact, ...additionalFacts],
      target: {
        image: depsAnalysis.depGraph.rootPkg.name,
      },
      identity: {
        type: depsAnalysis.depGraph.pkgManager.name,
        args,
      },
    },
    ...applicationDependenciesScanResults,
  ];

  return {
    scanResults,
  };
}
