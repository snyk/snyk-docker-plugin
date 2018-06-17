var fs = require('fs');
var path = require('path');
var subProcess = require('./sub-process');
var fetchSnykDockerAnalyzer = require('./fetch-snyk-docker-analyzer');
var debug = require('debug')('snyk');

module.exports = {
  inspect: inspect,
};

function inspect(root, targetFile) {
  const targetImage = root;
  return fetchSnykDockerAnalyzer()
  .then(function (analyzerBinaryPath) {
    return Promise.all([
      getMetaData(),
      getDependencies(analyzerBinaryPath, targetImage),
    ])
    .then(function (result) {
      return {
        plugin: result[0],
        package: result[1],
      };
    });
  })
}

function getMetaData() {
  return subProcess.execute('docker', ['version'])
  .then(function (output) {
    var runtime;
    versionMatch = /Version:\s+(.*)\n/.exec(output);
    if (versionMatch) {
      runtime = 'docker ' + versionMatch[1]
    }

    return {
      name: 'snyk-docker-plugin',
      runtime: runtime,
    };
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
  return subProcess.execute(
    analyzerBinaryPath,
    buildArgs(targetImage)
  )
  .then(function (output) {
    scanResults = JSON.parse(output);
    return convertDependecies(targetImage, scanResults);
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

function convertDependecies(targetImage, scanResults) {
  var targetSplit = targetImage.split(':');
  var imageName = targetSplit[0];
  var imageVersion = targetSplit[1] ? targetSplit[1] : 'latest';

  var analysisResults = scanResults.results.filter(function (res) {
    return res.Analysis && res.Analysis.length > 0;
  })[0];

  var pkgType;
  switch (analysisResults.AnalyzeType) {
    case 'Apt': {
      pkgType = 'deb';
      break;
    }
    default: {
      pkgType = analysisResults.AnalyzeType.toLowerCase()
    }
  }
  var root = {
    name: imageName,
    version: imageVersion,
    dockerOSRelease: scanResults.osRelease,
    packageFormatVersion: pkgType + ':0.0.1',
  };

  var pkgs = analysisResults['Analysis'];

  root.dependencies = pkgs.reduce(function (acc, pkg) {
    if (!pkg['Source']) {
      name = pkg['Name'];
    } else {
      name = pkg['Source'] + '/' + pkg['Name'];
    }
    version = pkg['Version'];

    acc[name] = {
      name: name,
      version: version,
      dependencies: {},
    }
    return acc;
  }, {});

  return root;
}

function buildArgs(targetImage) {
  var args = ['analyze', targetImage];
  return args;
}

function pathToPosix(fpath) {
  var parts = fpath.split(path.sep);
  return parts.join(path.posix.sep);
}
