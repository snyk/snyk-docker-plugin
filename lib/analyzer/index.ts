import * as Debug from "debug";
import { DockerOptions } from "../docker";
import * as dockerFile from "../docker-file";
import * as aptAnalyzer from "./apt-analyzer";
import * as binariesAnalyzer from "./binaries-analyzer";
import * as imageInspector from "./image-inspector";
import * as osReleaseDetector from "./os-release-detector";
import * as rpmAnalyzer from "./rpm-analyzer";

import apkInputDocker = require("./inputs/apk/docker");
import apkInputStatic = require("./inputs/apk/static");
import apkAnalyzer = require("./package-managers/apk");

export { analyze };

const debug = Debug("snyk");

async function analyze(
  targetImage: string,
  dockerfileAnalysis?: dockerFile.DockerFileAnalysis,
  options?: DockerOptions,
  analysisType?: string,
) {

  let apkDb: string = '';
  if (analysisType === 'static') {
    apkDb = await apkInputStatic.getApkDbFileContent(targetImage);
  } else { // assuming 'dynamic'
    apkDb = await apkInputDocker.getApkDbFileContent(targetImage, options);
  }

  const [imageInspection, osRelease] = await Promise.all([
    imageInspector.detect(targetImage, options),
    osReleaseDetector.detect(targetImage, dockerfileAnalysis, options),
  ]);

  const results = await Promise.all([
    apkAnalyzer.analyze(targetImage, apkDb),
    aptAnalyzer.analyze(targetImage, options),
    rpmAnalyzer.analyze(targetImage, options),
  ]).catch((err) => {
    debug(`Error while running analyzer: '${err.stderr}'`);
    throw new Error("Failed to detect installed OS packages");
  });

  const { installedPackages, pkgManager } = getInstalledPackages(
    results as any[],
  );
  let binaries;
  try {
    binaries = await binariesAnalyzer.analyze(
      targetImage,
      installedPackages,
      pkgManager,
      options,
    );
  } catch (err) {
    debug(`Error while running binaries analyzer: '${err}'`);
    throw new Error("Failed to detect binaries versions");
  }

  return {
    imageId: imageInspection.Id,
    osRelease,
    results,
    binaries,
    imageLayers: imageInspection.RootFS && imageInspection.RootFS.Layers,
  };
}

function getInstalledPackages(
  results: any[],
): { installedPackages: string[]; pkgManager?: string } {
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
