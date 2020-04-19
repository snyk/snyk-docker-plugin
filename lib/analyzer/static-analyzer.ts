import * as scanSchemas from "@snyk/scan-schemas";
import * as Debug from "debug";

import { getDockerArchiveLayersAndManifest } from "../extractor";
import { DockerArchiveManifest } from "../extractor/types";
import {
  getApkDbFileContent,
  getApkDbFileContentAction,
} from "../inputs/apk/static";
import {
  getAptDbFileContent,
  getDpkgFileContentAction,
  getExtFileContentAction,
} from "../inputs/apt/static";
import {
  getBinariesHashes,
  getNodeBinariesFileContentAction,
  getOpenJDKBinariesFileContentAction,
} from "../inputs/binaries/static";
import {
  getAptFiles,
  getDpkgPackageFileContentAction,
} from "../inputs/distroless/static";
import {
  getNodeAppFileContent,
  getNodeAppFileContentAction,
} from "../inputs/node/static";
import { getOsReleaseActions } from "../inputs/os-release/static";
import {
  getRpmDbFileContent,
  getRpmDbFileContentAction,
} from "../inputs/rpm/static";
import { ImageType, StaticAnalysisOptions } from "../types";
import * as nodeAnalyser from "./applications/node";
import * as osReleaseDetector from "./os-release";
import { analyze as apkAnalyze } from "./package-managers/apk";
import {
  analyze as aptAnalyze,
  analyzeDistroless as aptDistrolessAnalyze,
} from "./package-managers/apt";
import { analyze as rpmAnalyze } from "./package-managers/rpm";
import { ImageAnalysis, OSRelease, StaticAnalysis } from "./types";

const debug = Debug("snyk");

export async function analyze(
  targetImage: string,
  options: StaticAnalysisOptions,
): Promise<StaticAnalysis> {
  if (options.imageType !== ImageType.DockerArchive) {
    throw new Error("Unhandled image type");
  }

  const staticAnalysisActions = [
    getApkDbFileContentAction,
    getDpkgFileContentAction,
    getExtFileContentAction,
    getRpmDbFileContentAction,
    ...getOsReleaseActions,
    getNodeBinariesFileContentAction,
    getOpenJDKBinariesFileContentAction,
    getNodeAppFileContentAction,
  ];

  if (options.distroless) {
    staticAnalysisActions.push(getDpkgPackageFileContentAction);
  }

  const dockerArchive = await getDockerArchiveLayersAndManifest(
    options.imagePath,
    staticAnalysisActions,
  );

  const archiveLayers = dockerArchive.layers;

  // TODO add to other promises
  const scanResults: scanSchemas.base.ScanResult[] = []; // only app-scans right now, but we want all scans
  const tmp = getNodeAppFileContent(archiveLayers);
  if (Object.keys(tmp).length > 0) {
    const nodeScanResults = await nodeAnalyser.nodeLockFilesToData(tmp);
    scanResults.push(...nodeScanResults);
  }

  const [
    apkDbFileContent,
    aptDbFileContent,
    rpmDbFileContent,
  ] = await Promise.all([
    getApkDbFileContent(archiveLayers),
    getAptDbFileContent(archiveLayers),
    getRpmDbFileContent(archiveLayers),
  ]);

  let distrolessAptFiles: string[] = [];
  if (options.distroless) {
    distrolessAptFiles = getAptFiles(archiveLayers);
  }

  let osRelease: OSRelease;
  try {
    osRelease = await osReleaseDetector.detectStatically(archiveLayers);
  } catch (err) {
    debug(err);
    throw new Error("Failed to detect OS release");
  }

  let results: ImageAnalysis[];
  try {
    results = await Promise.all([
      apkAnalyze(targetImage, apkDbFileContent),
      aptAnalyze(targetImage, aptDbFileContent),
      rpmAnalyze(targetImage, rpmDbFileContent),
      aptDistrolessAnalyze(targetImage, distrolessAptFiles),
    ]);
  } catch (err) {
    debug(err);
    throw new Error("Failed to detect installed OS packages");
  }

  const imageId = imageIdFromArchiveManifest(dockerArchive.manifest);

  const binaries = getBinariesHashes(archiveLayers);

  return {
    imageId,
    osRelease,
    results,
    binaries,
    imageLayers: dockerArchive.manifest.Layers,
    scanResults,
  };
}

function imageIdFromArchiveManifest(manifest: DockerArchiveManifest): string {
  try {
    return manifest.Config.split(".")[0];
  } catch (err) {
    debug(manifest);
    debug(err);
    throw new Error("Failed to extract image ID from archive manifest");
  }
}
