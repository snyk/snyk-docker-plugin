var subProcess = require('./sub-process');
var fetchSnykDockerAnalyzer = require('./fetch-snyk-docker-analyzer');
var debug = require('debug')('snyk');

module.exports = {
  inspect: inspect,
};

function inspect(root) {
  var targetImage = root;
  return fetchSnykDockerAnalyzer()
    .then(function (analyzerBinaryPath) {
      return Promise.all([
        getRuntime(),
        getDependencies(analyzerBinaryPath, targetImage),
      ])
        .then(function (result) {
          var metadata = {
            name: 'snyk-docker-plugin',
            runtime: result[0],
            packageManager: result[1].packageManager,
            dockerImageId: result[1].imageId,
          };
          var package = result[1].package;
          return {
            plugin: metadata,
            package: package,
          };
        });
    });
}

function getRuntime() {
  return subProcess.execute('docker', ['version'])
    .then(function (output) {
      var versionMatch = /Version:\s+(.*)\n/.exec(output);
      if (versionMatch) {
        return 'docker ' + versionMatch[1];
      }
      return undefined;
    });
}

function handleCommonErrors(error, targetImage) {
  if (error.indexOf('command not found') !== -1) {
    throw new Error('Snyk docker CLI was not found');
  }
  if (error.indexOf('Cannot connect to the Docker daemon') !== -1) {
    throw new Error('Cannot connect to the Docker daemon. Is the docker'
    + ' daemon running?');
  }
  var ERROR_LOADING_IMAGE_STR = 'Error loading image from docker engine:';
  if (error.indexOf(ERROR_LOADING_IMAGE_STR) !== -1) {
    if (error.indexOf('reference does not exist') !== -1) {
      throw new Error(
        `Docker image was not found locally: ${targetImage}`);
    }
    if (error.indexOf('permission denied while trying to connect') !== -1) {
      var errString = error.split(ERROR_LOADING_IMAGE_STR)[1];
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

function getDependencies(analyzerBinaryPath, targetImage) {
  var result;
  return subProcess.execute(
    analyzerBinaryPath,
    buildArgs(targetImage)
  )
    .then(function (output) {
      result = parseAnalysisResults(output);
      return buildTree(
        targetImage, result.type, result.depInfosList, result.targetOS);
    })
    .then(function (package) {
      return {
        package: package,
        packageManager: result.type,
        imageId: result.imageId,
      };
    })
    .catch(function (error) {
      if (typeof error === 'string') {
        debug(`Error while running analyzer: '${error}'`);
        handleCommonErrors(error, targetImage);
        var errorMsg = error;
        var errorMatch = /msg="(.*)"/g.exec(errorMsg);
        if (errorMatch) {
          errorMsg = errorMatch[1];
        }
        throw new Error(errorMsg);
      }

      throw error;
    });
}

function parseAnalysisResults(analysisOut) {
  var analysisJson = JSON.parse(analysisOut);

  var analysisResult = analysisJson.results.filter(function (res) {
    return res.Analysis && res.Analysis.length > 0;
  })[0];

  if (!analysisResult) {
    throw new Error(
      'Failed to detect a supported Linux package manager (deb/rpm/apk)');
  }

  var depType;
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
  };
}

function buildTree(targetImage, depType, depInfosList, targetOS) {
  var targetSplit = targetImage.split(':');
  var imageName = targetSplit[0];
  var imageVersion = targetSplit[1] ? targetSplit[1] : 'latest';

  var root = {
    name: imageName,
    version: imageVersion,
    targetOS: targetOS,
    packageFormatVersion: depType + ':0.0.1',
    dependencies: {},
  };

  var depsMap = depInfosList.reduce(function (acc, depInfo) {
    var name = depInfo.Name;
    acc[name] = depInfo;
    return acc;
  }, {});

  var virtualDepsMap = depInfosList.reduce(function (acc, depInfo) {
    var providesNames = depInfo.Provides || [];
    providesNames.forEach(function (name) {
      acc[name] = depInfo;
    });
    return acc;
  }, {});

  var depsCounts = {};
  depInfosList.forEach(function (depInfo) {
    countDepsRecursive(
      depInfo.Name, new Set(), depsMap, virtualDepsMap, depsCounts);
  });
  var DEP_FREQ_THRESHOLD = 100;
  var tooFrequentDepNames = Object.keys(depsCounts)
    .filter(function (depName) {
      return depsCounts[depName] > DEP_FREQ_THRESHOLD;
    });

  var attachDeps = function (depInfos) {
    var depNamesToSkip = new Set(tooFrequentDepNames);
    depInfos.forEach(function (depInfo) {
      var subtree = buildTreeRecurisve(
        depInfo.Name, new Set(), depsMap, virtualDepsMap, depNamesToSkip);
      if (subtree) {
        root.dependencies[subtree.name] = subtree;
      }
    });
  };

  // attach (as direct deps) pkgs not marked auto-installed:
  var manuallyInstalledDeps = depInfosList.filter(function (depInfo) {
    return !depInfo.AutoInstalled;
  });
  attachDeps(manuallyInstalledDeps);

  // attach (as direct deps) pkgs marked as auto-insatalled,
  //  but not dependant upon:
  var notVisitedDeps = depInfosList.filter(function (depInfo) {
    var depName = depInfo.Name;
    return !(depsMap[depName]._visited);
  });
  attachDeps(notVisitedDeps);

  // group all the "too frequest" deps under a meta package:
  if (tooFrequentDepNames.length > 0) {
    var tooFrequentDeps = tooFrequentDepNames.map(function (name) {
      return depsMap[name];
    });

    var metaSubtree = {
      name: 'meta-common-packages',
      version: 'meta',
      dependencies: {},
    };

    tooFrequentDeps.forEach(function (depInfo) {
      var pkg = {
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
  var depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return null;
  }

  // "realName" as the argument depName might be a virtual pkg
  var realName = depInfo.Name;
  var fullName = depFullName(depInfo);
  if (ancestors.has(fullName) || depNamesToSkip.has(realName)) {
    return null;
  }

  var tree = {
    name: fullName,
    version: depInfo.Version,
  };

  if (depInfo._visited) {
    return tree;
  }
  depInfo._visited = true;

  var newAncestors = (new Set(ancestors)).add(fullName);

  var deps = depInfo.Deps || {};
  Object.keys(deps).forEach(function (depName) {
    var subTree = buildTreeRecurisve(
      depName, newAncestors, depsMap, virtualDepsMap, depNamesToSkip);
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
  var depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return;
  }

  // "realName" as the argument depName might be a virtual pkg
  var realName = depInfo.Name;
  if (ancestors.has(realName)) {
    return;
  }

  depCounts[realName] = (depCounts[realName] || 0) + 1;

  var newAncestors = (new Set(ancestors)).add(realName);
  var deps = depInfo.Deps || {};
  Object.keys(deps).forEach(function (depName) {
    countDepsRecursive(
      depName, newAncestors, depsMap, virtualDepsMap, depCounts);
  });
}

function depFullName(depInfo) {
  var fullName = depInfo.Name;
  if (depInfo.Source) {
    fullName = depInfo.Source + '/' + fullName;
  }
  return fullName;
}

function buildArgs(targetImage) {
  var args = ['analyze', targetImage];
  return args;
}
