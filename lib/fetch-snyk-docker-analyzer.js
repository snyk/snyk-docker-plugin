var os = require('os');
var fs = require('fs');
var fsExtra = require('fs-extra');
var path = require('path');
var request = require('request');
var ProgressBar = require('progress');
var pkgInfo = require('../package.json')

module.exports = fetch

const version = pkgInfo['snyk-docker-analyzer']['version'];

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
  return path.join(__dirname, '../bin/', version, name)
}

function fetch() {
  return new Promise((resolve, reject) => {
    try {
      var localPath = getBinaryLocalPath()
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

          var total = parseInt(res.headers['content-length'], 10);

          bar = new ProgressBar(`  downloading ${getBinaryName()} [:bar] :rate/Kbps :percent :etas remaining`, { // jscs:ignore maximumLineLength

            complete: '=',
            incomplete: '.',
            width: 20,
            total: total / 1000,
          });
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
          console.log('\n');
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
