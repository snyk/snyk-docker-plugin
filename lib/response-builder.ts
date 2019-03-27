// Module that provides functions to collect and build response after all
// analyses' are done.

import { DockerFilePackages } from './instruction-parser';

export { buildResponse };

function buildResponse(runtime, depsAnalysis, dockerfileAnalysis, options) {
  const deps = depsAnalysis.package.dependencies;
  const dockerfilePkgs = collectDockerfilePkgs(dockerfileAnalysis, deps);
  const pkg = packageRes(depsAnalysis, dockerfileAnalysis, dockerfilePkgs);
  const plugin = pluginMetadataRes(runtime, depsAnalysis);

  return {
    plugin,
    package: pkg,
  };
}

function pluginMetadataRes(runtime, depsAnalysis) {
  return {
    name: 'snyk-docker-plugin',
    runtime,
    packageManager: depsAnalysis.packageManager,
    dockerImageId: depsAnalysis.imageId,
    imageLayers: depsAnalysis.imageLayers,
  };
}

function packageRes(depsAnalysis, dockerfileAnalysis, dockerfilePkgs) {
  return {
    ...depsAnalysis.package,
    docker: {
      ...depsAnalysis.package.docker,
      ...dockerfileAnalysis,
      dockerfilePackages: dockerfilePkgs,
      binaries: depsAnalysis.binaries,
    },
  };
}

function collectDockerfilePkgs(dockerAnalysis, deps) {
  if (!dockerAnalysis) return;

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
      const sourceOrName = dependencyName.split('/')[0];
      const dockerfilePackage = dockerfilePackages[sourceOrName];

      if (dockerfilePackage) {
        collectDeps(dependencies[dependencyName]).forEach((dep) => {
          dockerfilePackages[dep.split('/')[0]] = { ...dockerfilePackage };
        });
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
