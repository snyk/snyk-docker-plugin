const os = require('os');
const fs = require('fs');
const fsExtra = require('fs-extra');
const path = require('path');
const needle = require('needle');
const tempDir = require('temp-dir');
const pkgInfo = require('../package.json');

module.exports = fetch;

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
        'https://snyk.io/resources/cli/plugins/docker-analyzer/' +
        `${version}/${getBinaryName()}`;

      console.log(`Downloading ${getBinaryName()} to ` +
        `${path.dirname(localPath)} ...`);

      needle.get(downloadUrl, function (error, res) {
        if (error) {
          reject(error);
          return;
        }

        if (res.statusCode >= 400) {
          var err = new Error(
            'Bad HTTP response for snyk-docker-analyzer download');
          err.statusCode = res.statusCode;
          err.body = res.body;
          reject(err);
          return;
        }

        // overwrite spinner label
        console.log('Download complete!' + ' '.repeat(55));

        fs.writeFileSync(localPath, res.body);
        const CHMOD_WITH_EXEC = 0755;
        fs.chmodSync(localPath, CHMOD_WITH_EXEC);
        resolve(localPath);
      });
    } catch (err) {
      reject(err);
    }
  });
}
