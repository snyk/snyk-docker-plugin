// Module that provides functions to collect and build response after all
// analyses' are done.

import { DockerFileAnalysis } from "./docker-file";
import { DockerFilePackages, instructionDigest } from "./instruction-parser";
import * as types from "./types";

export { buildResponse };

function buildResponse(
  runtime: string | undefined,
  depsAnalysis,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  manifestFiles: types.ManifestFile[],
  options,
): types.PluginResponse {
  const deps = depsAnalysis.package.dependencies;
  const dockerfilePkgs = collectDockerfilePkgs(dockerfileAnalysis, deps);
  const finalDeps = excludeBaseImageDeps(deps, dockerfilePkgs, options);
  annotateLayerIds(finalDeps, dockerfilePkgs);
  const plugin = pluginMetadataRes(runtime, depsAnalysis);
  const pkg = packageRes(
    depsAnalysis,
    dockerfileAnalysis,
    dockerfilePkgs,
    finalDeps,
  );

  const applicationDependenciesScanResults: types.ScannedProjectCustom[] =
    depsAnalysis.applicationDependenciesScanResults || [];

  const scannedProjects = [
    {
      packageManager: plugin.packageManager,
      depTree: pkg,
    },
    ...applicationDependenciesScanResults,
  ];

  if (manifestFiles.length > 0) {
    scannedProjects.push({
      scanType: types.ScanType.ManifestFiles,
      data: manifestFiles,
      packageManager: "PLEASE DON'T USE THIS",
      depTree: { dependencies: {} },
    } as types.ScannedProjectManifestFiles);
  }

  const scannedProjectsWithImageName = assignImageNameToScannedProjectMeta(
    pkg.name,
    scannedProjects,
  );

  return {
    plugin,
    scannedProjects: scannedProjectsWithImageName,
  };
}

/**
 * By sharing the same fields in the meta object, projects can be treated as related.
 */
function assignImageNameToScannedProjectMeta(
  imageName: string,
  scannedProjects: types.ScannedProjectCustom[],
): types.ScannedProjectCustom[] {
  return scannedProjects.map((project) => {
    if (project.meta === undefined) {
      project.meta = {};
    }
    project.meta.imageName = imageName;
    return project;
  });
}

function pluginMetadataRes(
  runtime: string | undefined,
  depsAnalysis,
): types.PluginMetadata {
  return {
    name: "snyk-docker-plugin",
    runtime,
    packageManager: depsAnalysis.packageManager,
    dockerImageId: depsAnalysis.imageId,
    imageLayers: depsAnalysis.imageLayers,
    rootFs: depsAnalysis.rootFsLayers,
  };
}

function packageRes(
  depsAnalysis,
  dockerfileAnalysis,
  dockerfilePkgs,
  deps,
): types.DepTree {
  return {
    ...depsAnalysis.package,
    dependencies: deps,
    docker: {
      ...depsAnalysis.package.docker,
      ...dockerfileAnalysis,
      dockerfilePackages: dockerfilePkgs,
      binaries: depsAnalysis.binaries,
    },
  };
}

function collectDockerfilePkgs(dockerAnalysis, deps) {
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
  dependencies,
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
function excludeBaseImageDeps(deps, dockerfilePkgs, options = {}) {
  if (!options["exclude-base-image-vulns"] || !dockerfilePkgs) {
    return deps;
  }

  return extractDockerfileDeps(deps, dockerfilePkgs);
}

function extractDockerfileDeps(allDeps, dockerfilePkgs) {
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
