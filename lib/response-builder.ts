import { legacy } from "@snyk/dep-graph";
import { StaticAnalysis } from "./analyzer/types";
import * as facts from "./facts";
// Module that provides functions to collect and build response after all
// analyses' are done.

import { instructionDigest } from "./dockerfile";
import { DockerFileAnalysis, DockerFilePackages } from "./dockerfile/types";
import { OCIDistributionMetadata } from "./extractor/oci-distribution-metadata";

import * as types from "./types";
import { truncateAdditionalFacts } from "./utils";
import { PLUGIN_VERSION } from "./version";

export { buildResponse };

async function buildResponse(
  depsAnalysis: StaticAnalysis & {
    depTree: types.DepTree;
    packageFormat: string;
  },
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  excludeBaseImageVulns: boolean,
  names?: string[],
  ociDistributionMetadata?: OCIDistributionMetadata,
  options?: Partial<types.PluginOptions>,
): Promise<types.PluginResponse> {
  const deps = depsAnalysis.depTree.dependencies;
  const dockerfilePkgs = dockerfileAnalysis?.dockerfilePackages ?? {};

  /** WARNING! Mutates the depTree.dependencies! */
  annotateLayerIds(deps, dockerfilePkgs);

  const finalDeps = excludeBaseImageDeps(
    deps,
    dockerfilePkgs,
    excludeBaseImageVulns,
  );

  // Apply the filtered dependencies back to the depTree
  depsAnalysis.depTree.dependencies = finalDeps;

  /** This must be called after all final changes to the DependencyTree. */
  const depGraph = await legacy.depTreeToGraph(
    depsAnalysis.depTree,
    depsAnalysis.packageFormat,
  );

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

  if (depsAnalysis.containerConfig) {
    const containerConfigFact: facts.ContainerConfigFact = {
      type: "containerConfig",
      data: {
        ...(depsAnalysis.containerConfig.User !== undefined && {
          user: depsAnalysis.containerConfig.User,
        }),
        ...(depsAnalysis.containerConfig.ExposedPorts !== undefined && {
          exposedPorts: depsAnalysis.containerConfig.ExposedPorts
            ? Object.keys(depsAnalysis.containerConfig.ExposedPorts)
            : null,
        }),
        ...(depsAnalysis.containerConfig.Env !== undefined && {
          env: depsAnalysis.containerConfig.Env,
        }),
        ...(depsAnalysis.containerConfig.Entrypoint !== undefined && {
          entrypoint: depsAnalysis.containerConfig.Entrypoint,
        }),
        ...(depsAnalysis.containerConfig.Cmd !== undefined && {
          cmd: depsAnalysis.containerConfig.Cmd,
        }),
        ...(depsAnalysis.containerConfig.Volumes !== undefined && {
          volumes: depsAnalysis.containerConfig.Volumes
            ? Object.keys(depsAnalysis.containerConfig.Volumes)
            : null,
        }),
        ...(depsAnalysis.containerConfig.WorkingDir !== undefined && {
          workingDir: depsAnalysis.containerConfig.WorkingDir,
        }),
        ...(depsAnalysis.containerConfig.StopSignal !== undefined && {
          stopSignal: depsAnalysis.containerConfig.StopSignal,
        }),
        ...(depsAnalysis.containerConfig.ArgsEscaped !== undefined && {
          argsEscaped: depsAnalysis.containerConfig.ArgsEscaped,
        }),
      },
    };
    additionalFacts.push(containerConfigFact);
  }

  if (depsAnalysis.history && depsAnalysis.history.length > 0) {
    const historyFact: facts.HistoryFact = {
      type: "history",
      data: depsAnalysis.history.map((entry) => ({
        ...(entry.created !== undefined && { created: entry.created }),
        ...(entry.author !== undefined && { author: entry.author }),
        ...(entry.created_by !== undefined && { createdBy: entry.created_by }),
        ...(entry.comment !== undefined && { comment: entry.comment }),
        ...(entry.empty_layer !== undefined && {
          emptyLayer: entry.empty_layer,
        }),
      })),
    };
    additionalFacts.push(historyFact);
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

  if (depsAnalysis.depTree.targetOS.prettyName) {
    const imageOsReleasePrettyNameFact: facts.ImageOsReleasePrettyNameFact = {
      type: "imageOsReleasePrettyName",
      data: depsAnalysis.depTree.targetOS.prettyName,
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
    const autoDetectedPackagesWithChildren = mapDepTreeToDockerfilePackages(
      autoDetectedPackages,
      deps,
    );

    const autoDetectedUserInstructionsFact: facts.AutoDetectedUserInstructionsFact =
      {
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

    if (names && names.length > 0) {
      const imageNamesFact: facts.ImageNamesFact = {
        type: "imageNames",
        data: { names },
      };
      appDepsScanResult.facts.push(imageNamesFact);
    }

    if (ociDistributionMetadata) {
      const metadataFact: facts.OCIDistributionMetadataFact = {
        type: "ociDistributionMetadata",
        data: ociDistributionMetadata,
      };
      appDepsScanResult.facts.push(metadataFact);
    }

    const appPluginVersionFact: facts.PluginVersionFact = {
      type: "pluginVersion",
      data: PLUGIN_VERSION,
    };
    appDepsScanResult.facts.push(appPluginVersionFact);

    return {
      ...appDepsScanResult,
      target: {
        image: depGraph.rootPkg.name,
      },
      ...(options &&
        options["target-reference"] && {
          targetReference: options["target-reference"],
        }),
    };
  });

  const args =
    depsAnalysis.platform !== undefined
      ? { platform: depsAnalysis.platform }
      : undefined;

  const depGraphFact: facts.DepGraphFact = {
    type: "depGraph",
    data: depGraph,
  };

  if (names) {
    if (names.length > 0) {
      const imageNameInfo = { names };
      const imageNamesFact: facts.ImageNamesFact = {
        type: "imageNames",
        data: imageNameInfo,
      };
      additionalFacts.push(imageNamesFact);
    }
  }

  if (ociDistributionMetadata) {
    const metadataFact: facts.OCIDistributionMetadataFact = {
      type: "ociDistributionMetadata",
      data: ociDistributionMetadata,
    };
    additionalFacts.push(metadataFact);
  }

  if (depsAnalysis.platform) {
    const platformFact: facts.PlatformFact = {
      type: "platform",
      data: depsAnalysis.platform,
    };
    additionalFacts.push(platformFact);
  }

  const pluginVersionFact: facts.PluginVersionFact = {
    type: "pluginVersion",
    data: PLUGIN_VERSION,
  };
  additionalFacts.push(pluginVersionFact);

  if (options?.parameterWarnings && options.parameterWarnings.length > 0) {
    const pluginWarningsFact: facts.PluginWarningsFact = {
      type: "pluginWarnings",
      data: {
        parameterChecks: options.parameterWarnings,
      },
    };
    additionalFacts.push(pluginWarningsFact);
  }

  const scanResults: types.ScanResult[] = [
    {
      facts: [depGraphFact, ...additionalFacts],
      target: {
        image: depGraph.rootPkg.name,
      },
      identity: {
        type: depGraph.pkgManager.name,
        args,
      },
      ...(options &&
        options["target-reference"] && {
          targetReference: options["target-reference"] ?? depGraph.rootPkg.name,
        }),
    },
    ...applicationDependenciesScanResults,
  ];

  const truncatedScanResults = scanResults.map((result) => ({
    ...result,
    facts: truncateAdditionalFacts(result.facts || []),
  }));

  return {
    scanResults: truncatedScanResults,
  };
}

// Returns the package source name from a dependency key. A package source refers
// to the top-level Linux package name, such as "bzip2" in "bzip2/libbz2-dev".
function packageSource(depKey: string): string {
  return depKey.split("/")[0];
}

function collectTransitiveDepKeys(pkg: types.DepTreeDep): string[] {
  if (!pkg.dependencies || Object.keys(pkg.dependencies).length === 0) {
    return [];
  }
  const keys = Object.keys(pkg.dependencies);
  const nested: string[] = [];
  for (const key of keys) {
    const childKeys = collectTransitiveDepKeys(pkg.dependencies![key]);
    for (const childKey of childKeys) {
      nested.push(childKey);
    }
  }
  return keys.concat(nested);
}

// Maps each dependency key (and its transitives) that matches a dockerfile-
// installed package to that package's instruction.
export function mapDepTreeToDockerfilePackages(
  dockerfilePkgs: DockerFilePackages,
  deps: { [depName: string]: types.DepTreeDep },
): DockerFilePackages {
  if (!dockerfilePkgs) {
    return {};
  }

  for (const rootKey of Object.keys(deps)) {
    const source = packageSource(rootKey);
    const instruction = dockerfilePkgs[rootKey] || dockerfilePkgs[source];
    if (!instruction) {
      continue;
    }

    // If package source was found in the tree, add it to the package object.
    if (!dockerfilePkgs[rootKey] && dockerfilePkgs[source]) {
      dockerfilePkgs[source] = instruction;
    }
    const transitiveKeys = collectTransitiveDepKeys(deps[rootKey]);
    for (const key of transitiveKeys) {
      dockerfilePkgs[key] = instruction;
    }
  }

  return dockerfilePkgs;
}

// If excludeBaseImageVulns is true, only retain dependencies that are
// dockerfile-introduced, as defined by dockerfilePkgs.
function excludeBaseImageDeps(
  deps: {
    [depName: string]: types.DepTreeDep;
  },
  dockerfilePkgs: DockerFilePackages | undefined,
  excludeBaseImageVulns: boolean,
) {
  if (!excludeBaseImageVulns || !dockerfilePkgs) {
    return deps;
  }

  return Object.keys(deps)
    .filter(
      (depName) =>
        dockerfilePkgs[depName] || dockerfilePkgs[packageSource(depName)],
    )
    .reduce((extractedDeps, depName) => {
      extractedDeps[depName] = deps[depName];
      return extractedDeps;
    }, {});
}

// Annotates dockerfile-introduced dependencies and sub-dependencies with the
// instruction ID. A dependency is identified as dockerfile-introduced if the
// dependency key or source was found in a dockerfile installation instruction.
function annotateLayerIds(
  deps: { [depName: string]: types.DepTreeDep },
  dockerfilePkgs: DockerFilePackages | undefined,
): void {
  if (!dockerfilePkgs) {
    return;
  }

  for (const rootKey of Object.keys(deps)) {
    const source = packageSource(rootKey);
    const dockerfileEntry = dockerfilePkgs[rootKey] || dockerfilePkgs[source];
    if (!dockerfileEntry) {
      continue;
    }

    const rootNode = deps[rootKey];
    const layerId = instructionDigest(dockerfileEntry.instruction);
    rootNode.labels = {
      ...(rootNode.labels || {}),
      dockerLayerId: layerId,
    };
    if (
      rootNode.dependencies &&
      Object.keys(rootNode.dependencies).length > 0
    ) {
      annotateSubtreeWithLayerId(rootNode.dependencies, layerId);
    }
  }
}

function annotateSubtreeWithLayerId(
  deps: { [depName: string]: types.DepTreeDep },
  dockerLayerId: string,
): void {
  for (const depKey of Object.keys(deps)) {
    const node = deps[depKey];
    node.labels = {
      ...(node.labels || {}),
      dockerLayerId,
    };
    if (node.dependencies && Object.keys(node.dependencies).length > 0) {
      annotateSubtreeWithLayerId(node.dependencies, dockerLayerId);
    }
  }
}
