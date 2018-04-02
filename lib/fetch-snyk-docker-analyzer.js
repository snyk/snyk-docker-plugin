const os = require('os');
const fs = require('fs');
const fsExtra = require('fs-extra');
const path = require('path');
const request = require('request');
const ciInfo = require('ci-info');
const ProgressBar = require('progress');
const pkgInfo = require('../package.json')

module.exports = fetch

const version = pkgInfo['snyk-docker-analyzer']['version'];

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
  return path.join(__dirname, '../bin/', version, name)
}

function fetch() {
  return new Promise((resolve, reject) => {
    try {
      const localPath = getBinaryLocalPath()
      if (fs.existsSync(localPath)) {
        return resolve(localPath);
      }
      fsExtra.ensureDirSync(path.dirname(localPath));
      const downloadUrl =
        `https://s3.amazonaws.com/snyk-docker-analyzer-releases/${version}/${getBinaryName()}`; // jscs:ignore maximumLineLength

      var bar;
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

          if (ciInfo.isCI) {
            console.log(`downloading ${getBinaryName()} ...`);
          } else {
            const total = parseInt(res.headers['content-length'], 10);
            bar = new ProgressBar(`downloading ${getBinaryName()} [:bar] :rate/Kbps :percent :etas remaining`, { // jscs:ignore maximumLineLength
              complete: '=',
              incomplete: '.',
              width: 20,
              total: total / 1000,
            });
          }
        })
        .on('data', function (chunk) {
          if (bar) {
            bar.tick(chunk.length / 1000);
          }
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
