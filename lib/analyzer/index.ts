import * as osReleaseDetector from './os-release-detector';
import * as imageIdDetector from './image-id-detector';
import * as apkAnalyzer from './apk-analyzer';
import * as aptAnalyzer from './apt-analyzer';
import * as rpmAnalyzer from './rpm-analyzer';
import * as binariesAnalyzer from './binaries-analyzer';
const debug = require('debug')('snyk');

export {
  analyze,
};

function analyze(targetImage: string) {
  return Promise.all([
    imageIdDetector.detect(targetImage),
    osReleaseDetector.detect(targetImage),
    Promise.all([
      apkAnalyzer.analyze(targetImage),
      aptAnalyzer.analyze(targetImage),
      rpmAnalyzer.analyze(targetImage),
    ]).catch((err) => {
      debug(`Error while running analyzer: '${err}'`);
      throw new Error('Failed to detect installed OS packages');
    }),
    binariesAnalyzer.analyze(targetImage)
    .catch((err) => {
      debug(`Error while running binaries analyzer: '${err}'`);
      throw new Error('Failed to detect binaries versions');
    }),
  ])
  .then(res => ({
    imageId: res[0],
    osRelease: res[1],
    results: res[2],
    binaries: res[3],
  }));
}
