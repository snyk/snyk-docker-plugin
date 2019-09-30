import * as Debug from "debug";
import { getDockerArchiveLayersAndManifest } from "../extractor";
import {
  getApkDbFileContent,
  getApkDbFileContentAction,
} from "../inputs/apk/static";
import {
  getAptDbFileContent,
  getDpkgFileContentAction,
  getExtFileContentAction,
} from "../inputs/apt/static";
import { getOsReleaseActions } from "../inputs/os-release/static";
import { ImageType, StaticAnalysisOptions } from "../types";
import * as osReleaseDetector from "./os-release";
import { analyze as apkAnalyze } from "./package-managers/apk";
import { analyze as aptAnalyze } from "./package-managers/apt";

const debug = Debug("snyk");

export async function analyze(
  targetImage: string,
  options: StaticAnalysisOptions,
) {
  if (!options.imagePath || options.imageType === undefined) {
    throw new Error("Missing required parameters for static analysis");
  }

  if (options.imageType !== ImageType.DockerArchive) {
    throw new Error("Unhandled image type");
  }

  const staticAnalysisActions = [
    getApkDbFileContentAction,
    getDpkgFileContentAction,
    getExtFileContentAction,
    // no RPM support yet
    ...getOsReleaseActions,
  ];

  const dockerArchive = await getDockerArchiveLayersAndManifest(
    options.imagePath,
    staticAnalysisActions,
  );

  const archiveLayers = dockerArchive.layers;

  const [apkDbFileContent, aptDbFileContent] = await Promise.all([
    getApkDbFileContent(archiveLayers),
    getAptDbFileContent(archiveLayers),
  ]);

  const osRelease = await osReleaseDetector
    .detectStatically(archiveLayers)
    .catch((err) => {
      debug(err);
      throw new Error("Failed to detect OS release");
    });

  const results = await Promise.all([
    apkAnalyze(targetImage, apkDbFileContent),
    aptAnalyze(targetImage, aptDbFileContent),
  ]).catch((err) => {
    debug(err);
    throw new Error("Failed to detect installed OS packages");
  });

  const imageId = targetImage;
  // Key binaries are not yet handled in static analysis.
  const binaries = [];

  return {
    imageId,
    osRelease,
    results,
    binaries,
    imageLayers: dockerArchive.manifest.Layers,
  };
}
