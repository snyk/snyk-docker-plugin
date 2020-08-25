import * as Debug from "debug";
import { normalize as normalizePath } from "path";
import { DockerOptions } from "../docker";
import * as dockerFile from "../docker-file";
import * as binariesAnalyzer from "../inputs/binaries/docker";
import * as imageInspector from "./image-inspector";
import * as osReleaseDetector from "./os-release";

import apkInputDocker = require("../inputs/apk/docker");
import aptInputDocker = require("../inputs/apt/docker");
import rpmInputDocker = require("../inputs/rpm/docker");
import apkAnalyzer = require("./package-managers/apk");
import aptAnalyzer = require("./package-managers/apt");
import rpmAnalyzer = require("./package-managers/rpm");
import { DynamicAnalysis, ImageAnalysis } from "./types";

const debug = Debug("snyk");

export async function analyze(
  targetImage: string,
  dockerfileAnalysis?: dockerFile.DockerFileAnalysis,
  options?: DockerOptions,
): Promise<DynamicAnalysis> {
  try {
    await imageInspector.pullIfNotLocal(targetImage, options);
  } catch (error) {
    debug(`Error while running analyzer: '${error}'`);
    throw new Error(
      "Docker error: image was not found locally and pulling failed: " +
        targetImage,
    );
  }

  const [imageInspection, osRelease] = await Promise.all([
    imageInspector.detect(targetImage, options),
    osReleaseDetector.detectDynamically(
      targetImage,
      dockerfileAnalysis,
      options,
    ),
  ]);

  const [
    apkDbFileContent,
    aptDbFileContent,
    rpmDbFileContent,
  ] = await Promise.all([
    apkInputDocker.getApkDbFileContent(targetImage, options),
    aptInputDocker.getAptDbFileContent(targetImage, options),
    rpmInputDocker.getRpmDbFileContent(targetImage, options),
  ]);

  let pkgManagerAnalysis: ImageAnalysis[];
  try {
    pkgManagerAnalysis = await Promise.all([
      apkAnalyzer.analyze(targetImage, apkDbFileContent),
      aptAnalyzer.analyze(targetImage, aptDbFileContent),
      rpmAnalyzer.analyze(targetImage, rpmDbFileContent),
    ]);
  } catch (error) {
    debug(`Error while running analyzer: '${error.stderr}'`);
    throw new Error("Failed to detect installed OS packages");
  }

  const { installedPackages, pkgManager } = getInstalledPackages(
    pkgManagerAnalysis as any[],
  );

  let binariesAnalysis: ImageAnalysis;
  try {
    binariesAnalysis = await binariesAnalyzer.analyze(
      targetImage,
      installedPackages,
      pkgManager,
      options,
    );
  } catch (error) {
    debug(`Error while running binaries analyzer: '${error}'`);
    throw new Error("Failed to detect binaries versions");
  }

  return {
    imageId: imageInspection.Id,
    osRelease,
    results: pkgManagerAnalysis,
    binaries: binariesAnalysis,
    imageLayers:
      imageInspection.RootFS && imageInspection.RootFS.Layers !== undefined
        ? imageInspection.RootFS.Layers.map((layer) => normalizePath(layer))
        : [],
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
