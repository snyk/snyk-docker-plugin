var fs = require('fs');
var path = require('path');
var subProcess = require('./sub-process');
var fetchSnykDockerAnalyzer = require('./fetch-snyk-docker-analyzer');

module.exports = {
  inspect: inspect,
};

function inspect(root, targetFile) {
  return fetchSnykDockerAnalyzer()
  .then(function (analyzerBinaryPath) {    
    return Promise.all([
      getMetaData(root, targetFile),
      getDependencies(analyzerBinaryPath, root, targetFile),
    ])
    .then(function (result) {
      return {
        plugin: result[0],
        package: result[1],
      };
    });
  })
  .catch(function (err) {
    console.log(err);
  })
}

function getMetaData(root, targetFile) {
  console.log(targetFile)
  return subProcess.execute('docker', ['version'], {cwd: root})
  .then(function (output) {
    var runtime;
    versionMatch = /Version:\s+(.*)\n/.exec(output);
    if (versionMatch) {
      runtime = versionMatch[1]
    }

    return {
      name: 'snyk-docker-plugin',
      runtime: runtime,
      targetFile: pathToPosix(targetFile),
    };
  });
}



function getDependencies(analyzerBinaryPath, command, targetFile) {
  return subProcess.execute(
    analyzerBinaryPath,
    buildArgs(targetFile)
  )
  .then(function (output) {
    scanResults = JSON.parse(output);
    return convertDependecies(targetFile, scanResults);
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
  })
}

function convertDependecies(targetFile, scanResults) {
  packageSplit = targetFile.split(':')
  packageName = packageSplit[0]
  if (packageSplit.length == 1) {
    packageVersion = 'latest'
  } else {
    packageVersion = packageSplit[1]
  }

  var scanResult = scanResults.filter(function (res) {
    return res.Analysis && res.Analysis.length > 0;
  })[0];

  var pkgType;
  switch (scanResult.AnalyzeType) {
    case 'Apt':
      pkgType = 'deb';
      break;
    default:
      pkgType = scanResult.AnalyzeType.toLowerCase()
  }

  packageData = {};
  packageData['name'] = packageName;
  packageData['version'] = packageVersion;
  packageData['from'] = [packageName + '@' + packageVersion];
  packageData['dependencies'] = {};
  packageData['packageFormatVersion'] = pkgType + ':0.0.1';
  analyzeType = scanResult['AnalyzeType'].toLowerCase()
  dependencies = scanResult['Analysis']
  dependencies.map(function (dependency) {
    dependencyName = dependency['Name'].split('/').pop(0)
    dependencyVersion = dependency['Version'] || dependency['Sha1']
    fullDependecnyName = dependencyName + '@' + dependencyVersion
    packageData['dependencies'][dependencyName] = {
      name: dependencyName,
      version: dependencyVersion,
      dependencies: [],
      from: [
        packageData['from'][0],
        fullDependecnyName,
      ],
    }
  });

  return packageData;
}

function buildArgs(targetFile) {
  var args = ['analyze',targetFile];
  return args;
}

function pathToPosix(fpath) {
  var parts = fpath.split(path.sep);
  return parts.join(path.posix.sep);
}
