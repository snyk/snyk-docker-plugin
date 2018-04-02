var fs = require('fs');
var path = require('path');
var subProcess = require('./sub-process');
var fetchSnykDockerAnalyzer = require('./fetch-snyk-docker-analyzer');

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

function getDependencies(analyzerBinaryPath, targetImage) {
  console.log(`analyzing ${targetImage} Docker image`);
  return subProcess.execute(
    analyzerBinaryPath,
    buildArgs(targetImage)
  )
  .then(function (output) {
    scanResults = JSON.parse(output);
    return Promise.resolve(convertDependecies(targetImage, scanResults));
  })
  .catch(function (error) {
    if (typeof error === 'string') {
      if (error.indexOf('command not found') !== -1) {
        throw new Error('Snyk docker CLI wasn\'t found')
      }
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
  targetSplit = targetImage.split(':');
  imageName = targetSplit[0];
  imageVersion = targetSplit[1];
  imageVersion = (imageVersion ? imageVersion : 'lateset');

  root = {};
  root.name = imageName;
  root.version = imageVersion;
  root.from = [imageName + '@' + imageVersion];

  var scanResult = scanResults.filter(function (res) {
    return res.Analysis && res.Analysis.length > 0;
  })[0];

  var pkgType;
  switch (scanResult.AnalyzeType) {
    case 'Apt': {
      pkgType = 'deb';
      break;
    }
    default: {
      pkgType = scanResult.AnalyzeType.toLowerCase()
    }
  }
  root.packageFormatVersion = pkgType + ':0.0.1';

  pkgs = scanResult['Analysis']

  root.dependencies = pkgs.reduce(function (acc, pkg) {
    name = pkg['Name'];
    version = pkg['Version'];

    acc[name] = {
      name: name,
      version: version,
      dependencies: {},
      from: [
        root['from'][0],
        name + '@' + version,
      ],
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
