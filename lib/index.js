var subProcess = require('./sub-process');
var fetchSnykDockerAnalyzer = require('./fetch-snyk-docker-analyzer');
var debug = require('debug')('snyk');

module.exports = {
  inspect: inspect,
};

function inspect(root, targetFile, options) {
  const targetImage = root;
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
      };
      var package = result[1].package;
      return {
        plugin: metadata,
        package: package,
      };
    });
  })
}

function getRuntime() {
  return subProcess.execute('docker', ['version'])
  .then(function (output) {
    versionMatch = /Version:\s+(.*)\n/.exec(output);
    if (versionMatch) {
      return 'docker ' + versionMatch[1]
    }
    return undefined;
  });
}

function handleCommonErrors(error, targetImage) {
  if (error.indexOf('command not found') !== -1) {
    throw new Error('Snyk docker CLI was not found')
  }
  if (error.indexOf('Cannot connect to the Docker daemon') !== -1) {
    throw new Error('Cannot connect to the Docker daemon. Is the docker'
    + ' daemon running?')
  }
  if ((error.indexOf('Error loading image from docker engine') !== -1) ||
      (error.indexOf('Error performing image analysis') !== -1)) {
    throw new Error('Docker image was not found: ' + targetImage)
  }
  if (error.indexOf('Error getting docker client:') !== -1) {
    throw new Error('Failed getting docker client')
  }
  if (error.indexOf('Error processing image:') !== -1) {
    throw new Error('Failed processing image:' + targetImage)
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
      targetImage, result.type, result.depInfosList, result.osRelease);
  })
  .then(function (package) {
    return {
      package: package,
      packageManager: result.type,
    };
  })
  .catch(function (error) {
    if (typeof error === 'string') {
      debug(`Error while running analyser: '${error}'`);
      handleCommonErrors(error, targetImage);
      errorMsg = error;
      errorMatch = /msg="(.*)"/g.exec(errorMsg)
      if (errorMatch) {
        errorMsg = errorMatch[1]
      }
      throw new Error(errorMsg);
    }

    throw error;
  })
}

function parseAnalysisResults(analysisOut) {
  var analysisJson = JSON.parse(analysisOut);

  var analysisResult = analysisJson.results.filter(function (res) {
    return res.Analysis && res.Analysis.length > 0;
  })[0];

  // TODO: if analysisResult is undefined -
  //  throw a nice error, or report 0 deps

  var depType;
  switch (analysisResult.AnalyzeType) {
    case 'Apt': {
      depType = 'deb';
      break;
    }
    default: {
      depType = analysisResult.AnalyzeType.toLowerCase()
    }
  }

  return {
    type: depType,
    depInfosList: analysisResult.Analysis,
    osRelease: analysisJson.osRelease,
  }
}

function buildTree(targetImage, depType, depInfosList, osRelease) {
  var targetSplit = targetImage.split(':');
  var imageName = targetSplit[0];
  var imageVersion = targetSplit[1] ? targetSplit[1] : 'latest';

  var root = {
    name: imageName,
    version: imageVersion,
    dockerOSRelease: osRelease,
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

  var attachDeps = function (depInfos) {
    depInfos.forEach(function (depInfo) {
      var subtree = buildTreeRecurisve(
        depInfo.Name, new Set(), depsMap, virtualDepsMap);
      if (subtree) {
        root.dependencies[subtree.name] = subtree;
      }
    })
  };

  // attach (as direct deps) pkgs not marked auto-installed:
  var manuallyInstalledDeps = depInfosList.filter(function (depInfo) {
    return !depInfo.AutoInstalled;
  })
  attachDeps(manuallyInstalledDeps);

  // attach (as direct deps) pkgs marked as auto-insatalled,
  //  but not dependant upon:
  var notVisitedDeps = depInfosList.filter(function (depInfo) {
    var depName = depInfo.Name;
    return !(depsMap[depName]._visited);
  })
  attachDeps(notVisitedDeps);

  return root;
}

function buildTreeRecurisve(
    depName, ancestors, depsMap, virtualDepsMap) {
  var depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return null;
  }

  var fullName = depFullName(depInfo);
  if (ancestors.has(fullName)) {
    return null;
  }

  const tree = {
    name: fullName,
    version: depInfo.Version,
  };

  //TODO: if we do this we can avoid tracking ancestors
  if (depInfo._visited) {
    return tree;
  }
  depInfo._visited = true;

  var newAncestors = (new Set(ancestors)).add(fullName);

  var deps = depInfo.Deps || {};
  Object.keys(deps).forEach(function (depName) {
    var subTree = buildTreeRecurisve(
      depName, newAncestors, depsMap, virtualDepsMap);
    if (subTree) {
      if (!tree.dependencies) {
        tree.dependencies = {};
      }
      tree.dependencies[subTree.name] = subTree;
    }
  });

  return tree;
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
