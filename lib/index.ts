const debug = require('debug')('snyk');

import * as analyzer from './analyzer';
import * as subProcess from './sub-process';
import * as dockerFile from './docker-file';
import {
  DockerFilePackages,
} from './instruction-parser';

export {
  inspect,
};

function inspect(root: string, targetFile?: string, options?: any) {
  const targetImage = root;
  return Promise.all([
    getRuntime(),
    getDependencies(targetImage),
    dockerFile.analyseDockerfile(targetFile),
  ])
    .then((result) => {
      const metadata = {
        name: 'snyk-docker-plugin',
        runtime: result[0],
        packageManager: result[1].packageManager,
        dockerImageId: result[1].imageId,
        imageLayers: result[1].imageLayers,
      };
      const pkg: any = result[1].package;
      const dockerfileAnalysis = result[2];
      const dockerfilePackages = dockerfileAnalysis
        ? getDockerfileDependencies(dockerfileAnalysis.dockerfilePackages,
                                    pkg.dependencies)
        : [];

      pkg.docker = pkg.docker || {};
      pkg.docker.binaries = result[1].binaries;
      pkg.docker = {
        ...pkg.docker,
        ...dockerfileAnalysis,
        dockerfilePackages,
      };

      return {
        plugin: metadata,
        package: pkg,
      };
    });
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

function getRuntime() {
  return subProcess.execute('docker', ['version'])
    .then((output) => {
      const versionMatch = /Version:\s+(.*)\n/.exec(output);
      if (versionMatch) {
        return 'docker ' + versionMatch[1];
      }
      return undefined;
    });
}

function handleCommonErrors(error, targetImage: string) {
  if (error.indexOf('command not found') !== -1) {
    throw new Error('Snyk docker CLI was not found');
  }
  if (error.indexOf('Cannot connect to the Docker daemon') !== -1) {
    throw new Error('Cannot connect to the Docker daemon. Is the docker'
    + ' daemon running?');
  }
  const ERROR_LOADING_IMAGE_STR = 'Error loading image from docker engine:';
  if (error.indexOf(ERROR_LOADING_IMAGE_STR) !== -1) {
    if (error.indexOf('reference does not exist') !== -1) {
      throw new Error(
        `Docker image was not found locally: ${targetImage}`);
    }
    if (error.indexOf('permission denied while trying to connect') !== -1) {
      let errString = error.split(ERROR_LOADING_IMAGE_STR)[1];
      errString = (errString || '').slice(0, -2); // remove trailing \"
      throw new Error(
        'Permission denied connecting to docker daemon. ' +
        'Please make sure user has the required permissions. ' +
        'Error string: ' + errString);
    }
  }
  if (error.indexOf('Error getting docker client:') !== -1) {
    throw new Error('Failed getting docker client');
  }
  if (error.indexOf('Error processing image:') !== -1) {
    throw new Error('Failed processing image:' + targetImage);
  }
}

function getDependencies(targetImage: string) {
  let result;
  return analyzer.analyze(targetImage)
    .then((output) => {
      result = parseAnalysisResults(output);
      return buildTree(
        targetImage, result.type, result.depInfosList, result.targetOS);
    })
    .then((pkg) => {
      return {
        package: pkg,
        packageManager: result.type,
        imageId: result.imageId,
        binaries: result.binaries,
        imageLayers: result.imageLayers,
      };
    })
    .catch((error) => {
      if (typeof error === 'string') {
        debug(`Error while running analyzer: '${error}'`);
        handleCommonErrors(error, targetImage);
        let errorMsg = error;
        const errorMatch = /msg="(.*)"/g.exec(errorMsg);
        if (errorMatch) {
          errorMsg = errorMatch[1];
        }
        throw new Error(errorMsg);
      }
      throw error;
    });
}

function parseAnalysisResults(analysisJson) {
  const analysisResult = analysisJson.results.filter((res) => {
    return res.Analysis && res.Analysis.length > 0;
  })[0];

  if (!analysisResult) {
    throw new Error(
      'Failed to detect a supported Linux package manager (deb/rpm/apk)');
  }

  let depType;
  switch (analysisResult.AnalyzeType) {
    case 'Apt': {
      depType = 'deb';
      break;
    }
    default: {
      depType = analysisResult.AnalyzeType.toLowerCase();
    }
  }

  return {
    imageId: analysisJson.imageId,
    targetOS: analysisJson.osRelease,
    type: depType,
    depInfosList: analysisResult.Analysis,
    binaries: analysisJson.binaries.Analysis,
    imageLayers: analysisJson.imageLayers,
  };
}

function buildTree(targetImage, depType, depInfosList, targetOS) {
  // A tag can only occur in the last section of a docker image name, so
  // check any colon separator after the final '/'. If there are no '/',
  // which is common when using Docker's official images such as
  // "debian:stretch", just check for ':'
  const finalSlash = targetImage.lastIndexOf('/');
  const hasVersion =
    (finalSlash >= 0 && targetImage.slice(finalSlash).includes(':'))
    || targetImage.includes(':');

  // Defaults for simple images from dockerhub, like "node" or "centos"
  let imageName = targetImage;
  let imageVersion = 'latest';

  // If we have a version, split on the last ':' to avoid the optional
  // port on a hostname (i.e. localhost:5000)
  if (hasVersion) {
    const versionSeparator = targetImage.lastIndexOf(':');
    imageName = targetImage.slice(0, versionSeparator);
    imageVersion = targetImage.slice(versionSeparator + 1);
  }

  const root = {
    // don't use the real image name to avoid scanning it as an issue
    name: 'docker-image|' + imageName,
    version: imageVersion,
    targetOS,
    packageFormatVersion: depType + ':0.0.1',
    dependencies: {},
  };

  const depsMap = depInfosList.reduce((acc, depInfo) => {
    const name = depInfo.Name;
    acc[name] = depInfo;
    return acc;
  }, {});

  const virtualDepsMap = depInfosList.reduce((acc, depInfo) => {
    const providesNames = depInfo.Provides || [];
    providesNames.forEach((name) => {
      acc[name] = depInfo;
    });
    return acc;
  }, {});

  const depsCounts = {};
  depInfosList.forEach((depInfo) => {
    countDepsRecursive(
      depInfo.Name, new Set(), depsMap, virtualDepsMap, depsCounts);
  });
  const DEP_FREQ_THRESHOLD = 100;
  const tooFrequentDepNames = Object.keys(depsCounts)
    .filter((depName) => {
      return depsCounts[depName] > DEP_FREQ_THRESHOLD;
    });

  const attachDeps = (depInfos) => {
    const depNamesToSkip = new Set(tooFrequentDepNames);
    depInfos.forEach((depInfo) => {
      const subtree = buildTreeRecurisve(
        depInfo.Name, new Set(), depsMap, virtualDepsMap, depNamesToSkip);
      if (subtree) {
        root.dependencies[subtree.name] = subtree;
      }
    });
  };

  // attach (as direct deps) pkgs not marked auto-installed:
  const manuallyInstalledDeps = depInfosList.filter((depInfo) => {
    return !depInfo.AutoInstalled;
  });
  attachDeps(manuallyInstalledDeps);

  // attach (as direct deps) pkgs marked as auto-insatalled,
  //  but not dependant upon:
  const notVisitedDeps = depInfosList.filter((depInfo) => {
    const depName = depInfo.Name;
    return !(depsMap[depName]._visited);
  });
  attachDeps(notVisitedDeps);

  // group all the "too frequest" deps under a meta package:
  if (tooFrequentDepNames.length > 0) {
    const tooFrequentDeps = tooFrequentDepNames.map((name) => {
      return depsMap[name];
    });

    const metaSubtree = {
      name: 'meta-common-packages',
      version: 'meta',
      dependencies: {},
    };

    tooFrequentDeps.forEach((depInfo) => {
      const pkg = {
        name: depFullName(depInfo),
        version: depInfo.Version,
      };
      metaSubtree.dependencies[pkg.name] = pkg;
    });

    root.dependencies[metaSubtree.name] = metaSubtree;
  }

  return root;
}

function buildTreeRecurisve(
  depName, ancestors, depsMap, virtualDepsMap, depNamesToSkip) {
  const depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return null;
  }

  // "realName" as the argument depName might be a virtual pkg
  const realName = depInfo.Name;
  const fullName = depFullName(depInfo);
  if (ancestors.has(fullName) || depNamesToSkip.has(realName)) {
    return null;
  }

  const tree: {
    name: string;
    version: string;
    dependencies?: any;
  } = {
    name: fullName,
    version: depInfo.Version,
  };

  if (depInfo._visited) {
    return tree;
  }
  depInfo._visited = true;

  const newAncestors = (new Set(ancestors)).add(fullName);

  const deps = depInfo.Deps || {};
  Object.keys(deps).forEach((name) => {
    const subTree = buildTreeRecurisve(
      name, newAncestors, depsMap, virtualDepsMap, depNamesToSkip);
    if (subTree) {
      if (!tree.dependencies) {
        tree.dependencies = {};
      }
      tree.dependencies[subTree.name] = subTree;
    }
  });

  return tree;
}

function countDepsRecursive(
  depName, ancestors, depsMap, virtualDepsMap, depCounts) {
  const depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return;
  }

  // "realName" as the argument depName might be a virtual pkg
  const realName = depInfo.Name;
  if (ancestors.has(realName)) {
    return;
  }

  depCounts[realName] = (depCounts[realName] || 0) + 1;

  const newAncestors = (new Set(ancestors)).add(realName);
  const deps = depInfo.Deps || {};
  Object.keys(deps).forEach((name) => {
    countDepsRecursive(
      name, newAncestors, depsMap, virtualDepsMap, depCounts);
  });
}

function depFullName(depInfo) {
  let fullName = depInfo.Name;
  if (depInfo.Source) {
    fullName = depInfo.Source + '/' + fullName;
  }
  return fullName;
}
