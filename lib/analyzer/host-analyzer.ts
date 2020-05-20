import * as Debug from "debug";
import { DockerOptions } from "../docker";
import * as dockerFile from "../docker-file";
import * as imageInspector from "./image-inspector";
import * as osReleaseDetector from "./os-release";

import apkInputHost = require("../inputs/apk/host");
import aptInputHost = require("../inputs/apt/host");
import rpmInputHost = require("../inputs/rpm/host");
import apkAnalyzer = require("./package-managers/apk");
import aptAnalyzer = require("./package-managers/apt");
import rpmAnalyzer = require("./package-managers/rpm");
import { AnalysisType, DynamicAnalysis, ImageAnalysis } from "./types";

const debug = Debug("snyk");

export async function analyze(
  targetImage: string,
  dockerfileAnalysis?: dockerFile.DockerFileAnalysis,
  options?: DockerOptions,
): Promise<DynamicAnalysis> {
  const [imageInspection, osRelease] = await Promise.all([
    imageInspector.detect(targetImage, options),
    osReleaseDetector.detectHost(targetImage, dockerfileAnalysis),
  ]);

  const [
    apkDbFileContent,
    aptDbFileContent,
    rpmDbFileContent,
  ] = await Promise.all([
    apkInputHost.getApkDbFileContent(),
    aptInputHost.getAptDbFileContent(),
    rpmInputHost.getRpmDbFileContent(),
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

  const binariesAnalysis = {
    Image: targetImage,
    AnalyzeType: AnalysisType.Binaries,
    Analysis: [],
  };

  return {
    imageId: imageInspection.Id,
    osRelease,
    results: pkgManagerAnalysis,
    binaries: binariesAnalysis,
    imageLayers: imageInspection.RootFS && imageInspection.RootFS.Layers,
  };
}
