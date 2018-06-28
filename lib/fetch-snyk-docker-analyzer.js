const os = require('os');
const fs = require('fs');
const fsExtra = require('fs-extra');
const path = require('path');
const request = require('request');
const tempDir = require('temp-dir');
const pkgInfo = require('../package.json');

module.exports = fetch

const version = pkgInfo['snyk-docker-analyzer'].version;

function getBinaryName() {
  const arch = os.arch();
  if (arch !== 'x64') {
    throw new Error(`Unsupported arch ${arch} - only amd64 is supported`);
  }
  const suffix = '';
  var platform = os.platform();
  if (platform === 'win32') {
    platform = 'windows';
    suffix = '.exe';
  }
  return `snyk-docker-analyzer-${platform}-amd64${suffix}`;
}

function getBinaryLocalPath() {
  const name = getBinaryName();
  return path.join(tempDir, 'snyk-docker-analyzer', version, name);
}

function fetch() {
  return new Promise((resolve, reject) => {
    try {
      const localPath = getBinaryLocalPath();
      if (fs.existsSync(localPath)) {
        return resolve(localPath);
      }
      fsExtra.ensureDirSync(path.dirname(localPath));
      const downloadUrl =
        `https://snyk.io/resources/cli/plugins/docker-analyzer/${version}/${getBinaryName()}`; // jscs:ignore maximumLineLength

      const fsStream = fs.createWriteStream(localPath + '.part');
      const req = request(downloadUrl);
      req
        .on('response', function (res) {
          if (res.statusCode >= 400) {
            var err = new Error(
              'Bad HTTP response for snyk-docker-analyzer download');
            err.statusCode = res.statusCode;
            fsStream.destroy();
            reject(err);
            req.abort();
            return;
          }

          console.log(
            `Downloading ${getBinaryName()} to ${path.dirname(getBinaryLocalPath())} ...`); // jscs:ignore maximumLineLength
        })
        .on('error', function (err) {
          reject(err);
        })
        .pipe(fsStream)
        .on('error', function (err) {
          fsStream.destroy();
          reject(err);
        })
        .on('finish', function () {
          // padding log() with some whitespaces to not mix with the CLI spinner
          console.log(`  => download complete.` + ' '.repeat(50));
          fs.renameSync(localPath + '.part', localPath);
          const CHMOD_WITH_EXEC = 0755;
          fs.chmodSync(localPath, CHMOD_WITH_EXEC);
          resolve(localPath);
        })
    } catch (err) {
      reject(err);
    }
  })
}
