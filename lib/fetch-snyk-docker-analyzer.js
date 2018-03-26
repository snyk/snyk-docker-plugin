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
      const snyk_docker_analyzer_url = `https://s3.amazonaws.com/snyk-docker-analyzer-releases/${version}/${getBinaryName()}`;
    
      var bar;
      const LOCAL_SNYK_DOCKER_ANALYZER_EXCEUTION_PERMISSION = 0755
      const req = request(snyk_docker_analyzer_url);
      req
        .on('response', function (res) {
          if (res.statusCode >= 400) {
            var err = new Error('Bad HTTP response for snyk-docker-analyzer download');
            err.statusCode = res.statusCode;
            reject(err);
            return;
          }

          var total = parseInt(res.headers['content-length'], 10);

          bar = new ProgressBar(`  downloading ${getBinaryName()} [:bar] :rate/Kbps :percent :etas remaining`, {
            complete: '=',
            incomplete: '.',
            width: 20,
            total: total / 1000
          });
        })
        .on('data', function (chunk) {
          if (bar) {
            bar.tick(chunk.length / 1000);
          }
        })
        .on('error', function (err) {
          console.log(err)
          reject(err)
        })
        .on('end', function () {
          console.log('\n');
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
