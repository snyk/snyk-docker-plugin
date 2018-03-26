var os = require('os');
var fs = require('fs');
var fsExtra = require('fs-extra');
var path = require('path');
var request = require('request');
var progress = require('request-progress');
var pkginfo = require('../package.json')

module.exports = fetch

const version = pkginfo['snyk-docker-analyzer']['version'];

function getBinaryName() {
  var arch = os.arch();  
  if (arch !== 'x64') {
    throw new Error(`Unsupported arch ${arch} - only amd64 is supported`);
  }
  var suffix = '';
  var platform = os.platform();
  if (platform === 'win32') {
    platform = 'windows';
    suffix = '.exe';
  }
  return `snyk-docker-analyzer-${platform}-amd64${suffix}`;
}

function getBinaryLocalPath() {
  var name = getBinaryName();
  return path.join(__dirname, '../dist/', version, name)
}

function createBinaryPath(binaryPath) {
  var binaryDirName = path.dirname(binaryPath);
  fsExtra.ensureDirSync(binaryDirName);
}

function fetch(binaryPath) {
  return new Promise((resolve, reject) => {
    try {
      var binaryPath = getBinaryLocalPath()
      if (fs.existsSync(binaryPath)) {
        return resolve(binaryPath);
      }
      createBinaryPath(binaryPath);
      // TODO: get the arch via api
      const SNYK_DOCKER_ANALYZER_URL = `https://s3.amazonaws.com/snyk-docker-analyzer-releases/${version}/${getBinaryName()}`;
    
      const LOCAL_SNYK_DOCKER_ANALYZER_EXCEUTION_PERMISSION = 0755
      progress(request(SNYK_DOCKER_ANALYZER_URL), {
      })
      .on('progress', function (state) {
          console.log('progress', state);
      })
      .on('error', function (err) {
          console.log(err)
          reject(err)
      })
      .on('end', function () {
          console.log('finished download file')
          fs.renameSync(binaryPath + '.part', binaryPath);
          fs.chmodSync(binaryPath, LOCAL_SNYK_DOCKER_ANALYZER_EXCEUTION_PERMISSION);
          resolve(binaryPath);
      })
      .pipe(fs.createWriteStream(binaryPath + '.part'))
    } catch (err) {
      reject(err);
    }
  })
}
