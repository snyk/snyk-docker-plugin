import { legacy } from "@snyk/dep-graph";
import { StaticAnalysis } from "./analyzer/types";
// Module that provides functions to collect and build response after all
// analyses' are done.

import { instructionDigest } from "./dockerfile";
import { DockerFileAnalysis, DockerFilePackages } from "./dockerfile/types";
import * as types from "./types";

export { buildResponse };

async function buildResponse(
  depsAnalysis: StaticAnalysis & {
    depTree: types.DepTree;
    packageManager: string;
  },
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  excludeBaseImageVulns: boolean,
): Promise<types.PluginResponse> {
  const deps = depsAnalysis.depTree.dependencies;
  const dockerfilePkgs = collectDockerfilePkgs(dockerfileAnalysis, deps);
  const finalDeps = excludeBaseImageDeps(
    deps,
    dockerfilePkgs,
    excludeBaseImageVulns,
  );
  /** WARNING! Mutates the depTree.dependencies! */
  annotateLayerIds(finalDeps, dockerfilePkgs);

  /** This must be called after all final changes to the DependencyTree. */
  const depGraph = await legacy.depTreeToGraph(
    depsAnalysis.depTree,
    depsAnalysis.packageManager,
  );

  const additionalOsDepsFacts: types.Fact[] = [];

  const hashes = depsAnalysis.binaries;
  if (hashes && hashes.length > 0) {
    additionalOsDepsFacts.push({
      type: "keyBinariesHashes",
      data: hashes,
    });
  }

  if (dockerfileAnalysis) {
    additionalOsDepsFacts.push({
      type: "dockerfileAnalysis",
      data: dockerfileAnalysis,
    });
  }

  if (depsAnalysis.imageId) {
    additionalOsDepsFacts.push({
      type: "imageId",
      data: depsAnalysis.imageId,
    });
  }

  if (depsAnalysis.imageLayers && depsAnalysis.imageLayers.length > 0) {
    additionalOsDepsFacts.push({
      type: "imageLayers",
      data: depsAnalysis.imageLayers,
    });
  }

  if (
    depsAnalysis.rootFsLayers &&
    Array.isArray(depsAnalysis.rootFsLayers) &&
    depsAnalysis.rootFsLayers.length > 0
  ) {
    additionalOsDepsFacts.push({
      type: "rootFs",
      data: depsAnalysis.rootFsLayers,
    });
  }

  if (depsAnalysis.depTree.targetOS.prettyName) {
    additionalOsDepsFacts.push({
      type: "imageOsReleasePrettyName",
      data: depsAnalysis.depTree.targetOS.prettyName,
    });
  }

  const manifestFiles =
    depsAnalysis.manifestFiles.length > 0
      ? depsAnalysis.manifestFiles
      : undefined;
  if (manifestFiles) {
    additionalOsDepsFacts.push({
      type: "imageManifestFiles",
      data: manifestFiles,
    });
  }

  const applicationDependenciesScanResults: types.ScanResult[] = (
    depsAnalysis.applicationDependenciesScanResults || []
  ).map((appDepsScanResult) => ({
    ...appDepsScanResult,
    target: {
      image: depGraph.rootPkg.name,
    },
  }));

  const args =
    depsAnalysis.platform !== undefined
      ? { platform: depsAnalysis.platform }
      : undefined;

  const scanResults: types.ScanResult[] = [
    {
      facts: [
        {
          type: "depGraph",
          data: depGraph,
        },
        ...additionalOsDepsFacts,
      ],
      target: {
        image: depGraph.rootPkg.name,
      },
      identity: {
        type: depGraph.pkgManager.name,
        args,
      },
    },
    ...applicationDependenciesScanResults,
  ];

  return {
    scanResults,
  };
}

function collectDockerfilePkgs(
  dockerAnalysis: DockerFileAnalysis | undefined,
  deps: {
    [depName: string]: types.DepTreeDep;
  },
) {
  if (!dockerAnalysis) {
    return;
  }

  return getDockerfileDependencies(dockerAnalysis.dockerfilePackages, deps);
}

// Iterate over the dependencies list; if one is introduced by the dockerfile,
// flatten its dependencies and append them to the list of dockerfile
// packages. This gives us a reference of all transitive deps installed via
// the dockerfile, and the instruction that installed it.
function getDockerfileDependencies(
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

// Skip processing if option disabled or dockerfilePkgs is undefined. We
// can't exclude anything in that case, because we can't tell which deps are
// from dockerfile and which from base image.
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

  return extractDockerfileDeps(deps, dockerfilePkgs);
}

function extractDockerfileDeps(
  allDeps: {
    [depName: string]: types.DepTreeDep;
  },
  dockerfilePkgs: DockerFilePackages,
) {
  return Object.keys(allDeps)
    .filter((depName) => dockerfilePkgs[depName])
    .reduce((extractedDeps, depName) => {
      extractedDeps[depName] = allDeps[depName];
      return extractedDeps;
    }, {});
}

function annotateLayerIds(deps, dockerfilePkgs) {
  if (!dockerfilePkgs) {
    return;
  }

  for (const dep of Object.keys(deps)) {
    const pkg = deps[dep];
    const dockerfilePkg = dockerfilePkgs[dep];
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
