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

export {
  buildResponse,
  expandDockerfilePackages,
  excludeBaseImageDeps,
  annotateWithLayerIds,
};

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

  // Expand both the Dockerfile packages and the auto-detected user instructions packages,
  // storing the results back to the original objects.
  if (dockerfileAnalysis?.dockerfilePackages) {
    dockerfileAnalysis.dockerfilePackages = expandDockerfilePackages(
      dockerfileAnalysis.dockerfilePackages,
      deps,
    );
  }

  if (depsAnalysis.autoDetectedUserInstructions?.dockerfilePackages) {
    depsAnalysis.autoDetectedUserInstructions.dockerfilePackages =
      expandDockerfilePackages(
        depsAnalysis.autoDetectedUserInstructions.dockerfilePackages,
        deps,
      );
  }

  // Select a dockerfilePackages object to use for the annotation and exclusion of base image dependencies.
  // Prioritize the Dockerfile packages over the auto-detected user instructions packages.
  const dockerfilePkgs =
    dockerfileAnalysis?.dockerfilePackages ||
    depsAnalysis.autoDetectedUserInstructions?.dockerfilePackages;

  const finalDeps = excludeBaseImageDeps(
    deps,
    dockerfilePkgs,
    excludeBaseImageVulns,
  );
  annotateWithLayerIds(finalDeps, dockerfilePkgs);

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
  if (depsAnalysis.baseRuntimes && depsAnalysis.baseRuntimes.length > 0) {
    const baseRuntimesFact: facts.BaseRuntimesFact = {
      type: "baseRuntimes",
      data: depsAnalysis.baseRuntimes,
    };
    additionalFacts.push(baseRuntimesFact);
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
    const autoDetectedUserInstructionsFact: facts.AutoDetectedUserInstructionsFact =
      {
        type: "autoDetectedUserInstructions",
        data: {
          dockerfileLayers: autoDetectedLayers,
          dockerfilePackages: autoDetectedPackages!,
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

/**
 * Returns the package source name from a full dependency name.
 *
 * A package source refers to the top-level package name, such as "bzip2" in "bzip2/libbz2-dev".
 *
 * @param depName - The full dependency name.
 * @returns The package source name.
 */
function packageSource(depName: string): string {
  return depName.split("/")[0];
}

/**
 * Expands the list of packages explicitly requested in the Dockerfile to include all transitive dependencies.
 *
 * The returned package map is keyed by the full dependency names. Package names extracted from the Dockerfile
 * (typically in the form of source segments) are copied from the input map into the returned map to maintain
 * compatibility with the CLI dockerfile-attribution logic.
 *
 * @param dockerfilePackages - The packages explicitly requested in a Dockerfile.
 * @param deps - The dependencies of the image.
 * @returns A map of packages attributed to the Dockerfile.
 */
function expandDockerfilePackages(
  dockerfilePackages: DockerFilePackages,
  deps: { [depName: string]: types.DepTreeDep },
): DockerFilePackages {
  const expandedPkgs = { ...dockerfilePackages };

  function collectChildPackages(node: types.DepTreeDep, parentEntry: any) {
    if (!node.dependencies) {
      return;
    }
    for (const childKey of Object.keys(node.dependencies)) {
      if (!expandedPkgs[childKey]) {
        expandedPkgs[childKey] = parentEntry;
        collectChildPackages(node.dependencies[childKey], parentEntry);
      }
    }
  }

  for (const rootKey of Object.keys(deps)) {
    const source = packageSource(rootKey);
    const dockerfileEntry = expandedPkgs[rootKey] || expandedPkgs[source];
    if (dockerfileEntry) {
      // Ensure the full dependency name is in the expanded packages.
      expandedPkgs[rootKey] = dockerfileEntry;
      collectChildPackages(deps[rootKey], dockerfileEntry);
    }
  }

  return expandedPkgs;
}

/**
 * Excludes base image dependencies from the dependency tree if excludeBaseImageVulns is true.
 *
 * @param deps - The dependencies of the image.
 * @param dockerfilePkgs - The expanded packages attributed to the Dockerfile.
 * @param excludeBaseImageVulns - Whether to exclude base image dependencies.
 * @returns The dependencies of the image.
 */
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
    .filter((depName) => dockerfilePkgs[depName])
    .reduce((extractedDeps, depName) => {
      extractedDeps[depName] = deps[depName];
      return extractedDeps;
    }, {});
}

/**
 * Annotates the dependency tree with layer IDs. Mutates the recieved dependency tree.
 *
 * @param deps - The dependencies of the image.
 * @param dockerfilePkgs - The expanded packages attributed to the Dockerfile.
 */
function annotateWithLayerIds(
  deps: { [depName: string]: types.DepTreeDep },
  dockerfilePkgs: DockerFilePackages | undefined,
): void {
  if (!dockerfilePkgs) {
    return;
  }

  function annotateRecursive(currentDeps: {
    [depName: string]: types.DepTreeDep;
  }) {
    for (const depKey of Object.keys(currentDeps)) {
      const node = currentDeps[depKey];
      const dockerfileEntry = dockerfilePkgs![depKey];

      if (dockerfileEntry) {
        node.labels = {
          ...(node.labels || {}),
          dockerLayerId: instructionDigest(dockerfileEntry.instruction),
        };

        // Only progress down the dependency tree if the current node is a dockerfile package.
        if (node.dependencies) {
          annotateRecursive(node.dependencies);
        }
      }
    }
  }

  annotateRecursive(deps);
}
