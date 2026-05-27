import { legacy } from "@snyk/dep-graph";
import { IntroducingLayerByPackage, StaticAnalysis } from "./analyzer/types";
import * as facts from "./facts";
// Module that provides functions to collect and build response after all
// analyses' are done.

import { instructionDigest } from "./dockerfile";
import { DockerFileAnalysis, DockerFilePackages } from "./dockerfile/types";
import { OCIDistributionMetadata } from "./extractor/oci-distribution-metadata";

import { computeScanPayloadMetrics } from "./scan-payload-metrics";
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

  // Expand dockerfile packages and auto detected user instructions if
  // they are provided. These objects are mutated in place, ensuring the
  // expanded packages are used in the subsequent steps and fact building.
  if (dockerfileAnalysis?.dockerfilePackages) {
    getUserInstructionDeps(dockerfileAnalysis.dockerfilePackages, deps);
  }
  if (depsAnalysis.autoDetectedUserInstructions?.dockerfilePackages) {
    getUserInstructionDeps(
      depsAnalysis.autoDetectedUserInstructions.dockerfilePackages,
      deps,
    );
  }

  const dockerfilePkgs =
    dockerfileAnalysis?.dockerfilePackages ??
    depsAnalysis.autoDetectedUserInstructions?.dockerfilePackages;

  if (dockerfilePkgs) {
    const finalDeps = excludeBaseImageDeps(
      deps,
      dockerfilePkgs,
      excludeBaseImageVulns,
    );
    annotateLayerIds(finalDeps, dockerfilePkgs);
    depsAnalysis.depTree.dependencies = finalDeps;
  }

  // `dockerLayerDiffId` is the new layer-identity label introduced by the
  // vulns-by-layer feature. It carries the diffID (`sha256:...`) of the
  // rootfs layer that introduced each package
  if (depsAnalysis.introducingLayerByPackage?.size) {
    annotateDockerLayerDiffIds(
      depsAnalysis.depTree.dependencies,
      depsAnalysis.introducingLayerByPackage,
    );
  }

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

  let historyFact: facts.HistoryFact | undefined;
  if (depsAnalysis.history && depsAnalysis.history.length > 0) {
    historyFact = {
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

  let rootFsFact: facts.RootFsFact | undefined;
  if (
    depsAnalysis.rootFsLayers &&
    Array.isArray(depsAnalysis.rootFsLayers) &&
    depsAnalysis.rootFsLayers.length > 0
  ) {
    rootFsFact = {
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
          dockerfilePackages: autoDetectedPackages,
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

    // TODO(vulns-by-layer, app-scan milestone): re-enable when app-package
    // layer attribution lands. The vulns-by-layer design duplicates `rootFs`
    // and `history` onto every container scan result so Registry can perform
    // the diffID -> instruction join per-monitor without a cross-scan-result
    // lookup. The first milestone only attributes OS packages, so app scan
    // results have no `dockerLayerDiffId`-labelled nodes to join against —
    // attaching the facts now would be dead weight in `container-monitor-data`
    // until the app-side label emission ships. Restore the block below once
    // app-package attribution is in place.
    //
    // if (depsAnalysis.introducingLayerByPackage) {
    //   if (rootFsFact) {
    //     appDepsScanResult.facts.push(rootFsFact);
    //   }
    //   if (historyFact) {
    //     appDepsScanResult.facts.push(historyFact);
    //   }
    // }

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

  const scanPayloadMetrics = computeScanPayloadMetrics(truncatedScanResults);

  return {
    scanResults: truncatedScanResults,
    analytics: [
      {
        name: "containerScanPayloadMetrics",
        data: scanPayloadMetrics,
      },
    ],
  };
}

/**
 * Expands the provided dockerfile packages to include transitive dependencies.
 * Transitive dependencies are keyed by their source segments.
 *
 * @important
 * mutates the provided `dockerfilePackages` object.
 *
 * @warning
 * **Known Issue:** In some scenarios, this function can cause over-attribution of
 * dependencies to the dockerfile because the `dockerfilePackages` object is mutated
 * while iterating. This behavior is retained for downstream compatibility.
 *
 * @param dockerfilePackages - The dockerfile packages to expand.
 * @param dependencies - The dependencies of the image.
 * @returns The expanded dockerfile packages.
 */
function getUserInstructionDeps(
  dockerfilePackages: DockerFilePackages,
  dependencies: {
    [depName: string]: types.DepTreeDep;
  },
): DockerFilePackages {
  for (const dependencyName in dependencies) {
    if (dependencies.hasOwnProperty(dependencyName)) {
      const sourceOrName = dependencyName.split("/")[0];
      const dockerfilePackage = dockerfilePackages[sourceOrName];

      if (dockerfilePackage) {
        for (const dep of collectDeps(dependencies[dependencyName])) {
          dockerfilePackages[dep.split("/")[0]] = { ...dockerfilePackage };
        }
      }
    }
  }

  return dockerfilePackages;
}

function collectDeps(pkg) {
  // ES5 doesn't have Object.values, so replace with Object.keys() and map()
  return pkg.dependencies
    ? Object.keys(pkg.dependencies)
        .map((name) => pkg.dependencies[name])
        .reduce((allDeps, pkg) => {
          return [...allDeps, ...collectDeps(pkg)];
        }, Object.keys(pkg.dependencies))
    : [];
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
    .filter((depName) => {
      if (dockerfilePkgs[depName] !== undefined) {
        return true;
      }
      const source = depName.split("/")[0];
      return dockerfilePkgs[source] !== undefined;
    })
    .reduce((extractedDeps, depName) => {
      extractedDeps[depName] = deps[depName];
      return extractedDeps;
    }, {});
}

/**
 * Annotates the dependencies with the layer ID of the Dockerfile
 * instruction that installed them.
 *
 * @important
 * mutates the provided `deps` object.
 *
 * @param deps - The dependencies of the image.
 * @param dockerfilePkgs - The expanded packages attributed to the Dockerfile.
 */
function annotateLayerIds(
  deps: {
    [depName: string]: types.DepTreeDep;
  },
  dockerfilePkgs: DockerFilePackages | undefined,
) {
  if (!dockerfilePkgs) {
    return;
  }

  for (const dep of Object.keys(deps)) {
    const pkg = deps[dep];
    const pkgSource = dep.split("/")[0];
    const dockerfilePkg = dockerfilePkgs[dep] || dockerfilePkgs[pkgSource];
    if (dockerfilePkg) {
      pkg.labels = {
        ...(pkg.labels || {}),
        dockerLayerId: instructionDigest(dockerfilePkg.instruction),
      };
    }
    if (pkg.dependencies) {
      annotateLayerIds(pkg.dependencies, dockerfilePkgs);
    }
  }
}

/**
 * Walks the dep tree and stamps `dockerLayerDiffId` on every node that has
 * an entry in the package -> diffID map produced by
 * `computeOsLayerAttribution`. The label survives `legacy.depTreeToGraph`
 * conversion and surfaces as `node.info.labels.dockerLayerDiffId` on the
 * resulting dep-graph node — the contract Registry's read-path join
 * depends on.
 *
 * Lookup key shape (`${name}@${version}`) matches what the attribution
 * producer mints via `depFullName(pkg)@${version}`; the dep-tree builder
 * uses the same `depFullName` for its node names, so the join is direct.
 *
 * @important mutates the provided `deps` object.
 */
function annotateDockerLayerDiffIds(
  deps: {
    [depName: string]: types.DepTreeDep;
  },
  introducingLayerByPackage: IntroducingLayerByPackage,
) {
  for (const depName of Object.keys(deps)) {
    const pkg = deps[depName];
    const diffID = introducingLayerByPackage.get(`${pkg.name}@${pkg.version}`);
    if (diffID) {
      pkg.labels = {
        ...(pkg.labels || {}),
        dockerLayerDiffId: diffID,
      };
    }
    if (pkg.dependencies) {
      annotateDockerLayerDiffIds(pkg.dependencies, introducingLayerByPackage);
    }
  }
}
