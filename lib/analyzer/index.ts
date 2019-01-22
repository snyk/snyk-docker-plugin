import * as osReleaseDetector from './os-release-detector';
import * as imageInspector from './image-inspector';
import * as apkAnalyzer from './apk-analyzer';
import * as aptAnalyzer from './apt-analyzer';
import * as rpmAnalyzer from './rpm-analyzer';
import * as binariesAnalyzer from './binaries-analyzer';
const debug = require('debug')('snyk');

export {
  analyze,
};

async function analyze(targetImage: string) {
  const [
    imageInspection,
    osRelease,
    results,
  ] = await Promise.all([
    imageInspector.detect(targetImage),
    osReleaseDetector.detect(targetImage),
    Promise.all([
      apkAnalyzer.analyze(targetImage),
      aptAnalyzer.analyze(targetImage),
      rpmAnalyzer.analyze(targetImage),
    ]).catch((err) => {
      debug(`Error while running analyzer: '${err}'`);
      throw new Error('Failed to detect installed OS packages');
    }),

  ]);

  const { installedPackages, pkgManager } =
    getInstalledPackages(results as any[]);
  let binaries;
  try {
    binaries = await binariesAnalyzer.analyze(
      targetImage, installedPackages, pkgManager);
  } catch (err) {
    debug(`Error while running binaries analyzer: '${err}'`);
    throw new Error('Failed to detect binaries versions');
  }

  return {
    imageId: imageInspection.Id,
    osRelease,
    results,
    binaries,
    imageLayers: imageInspection.RootFS && imageInspection.RootFS.Layers,
  };
}

function getInstalledPackages(results: any[]):
 {installedPackages: string[], pkgManager?: string} {
  const dockerAnalysis = results.find((res) => {
    return res.Analysis && res.Analysis.length > 0;
  });

  if (!dockerAnalysis) {
    return { installedPackages: [] };
  }
  const installedPackages = dockerAnalysis.Analysis.map((pkg) => pkg.Name);
  let pkgManager = dockerAnalysis.AnalyzeType;
  if (pkgManager) {
    pkgManager = pkgManager.toLowerCase();
  }
  return { installedPackages, pkgManager };
}
