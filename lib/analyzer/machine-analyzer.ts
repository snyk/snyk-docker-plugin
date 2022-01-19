import * as Debug from "debug";
import * as os from "os";
import { DockerFileAnalysis } from "../dockerfile";
import * as archiveExtractor from "../extractor";
import {
  getGoModulesContentAction,
  goModulesToScannedProjects,
} from "../go-parser";
import { getBufferContent, getElfFileContent, getFileContent } from "../inputs";
import {
  // getApkDbFileContent,
  // getApkDbFileContentFromMachine
  getApkDbFileContentAction,
} from "../inputs/apk/static";
import {
  // getAptDbFileContent,
  getDpkgFileContentActionMachine,
  // getDpkgFileContentAction,
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
import * as filePatternStatic from "../inputs/file-pattern/static";
import { getJarFileContentAction } from "../inputs/java/static";
import { getNodeAppFileContentAction } from "../inputs/node/static";
import { getOsReleaseActions } from "../inputs/os-release/static";
import {
  getRpmDbFileContent,
  getRpmDbFileContentAction,
} from "../inputs/rpm/static";
import { isTrue } from "../option-utils";
import { ImageType, ManifestFile, PluginOptions } from "../types";
import { nodeFilesToScannedProjects } from "./applications";
import { jarFilesToScannedProjects } from "./applications/java";
import { AppDepsScanResultWithoutTarget } from "./applications/types";
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
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  imagePath: string,
  globsToFind: { include: string[]; exclude: string[] },
  options: Partial<PluginOptions>,
): Promise<StaticAnalysis> {
  const staticAnalysisActions = [
    // getApkDbFileContentAction,
    getDpkgFileContentActionMachine,
    // getExtFileContentAction,
    // getRpmDbFileContentAction,
    // ...getOsReleaseActions,
    // getNodeBinariesFileContentAction,
    // getOpenJDKBinariesFileContentAction,
    // getDpkgPackageFileContentAction,
  ];

  const [
    // apkDbFileContent,
    aptDbFileContent,
    // rpmDbFileContent,
  ] = await Promise.all([
    // getApkDbFileContentFromMachine(),
    getDpkgFileContentActionMachine(),
    // getRpmDbFileContent(),
  ]);

  let osRelease: OSRelease;
  try {
    // osRelease = await osReleaseDetector.detectStatically(
    //   extractedLayers,
    //   dockerfileAnalysis,
    // );

    osRelease = {
      name: "string",
      version: "string",
      prettyName: "string",
    };
  } catch (err) {
    debug(`Could not detect OS release: ${JSON.stringify(err)}`);
    throw new Error("Failed to detect OS release");
  }

  let results: ImageAnalysis[];
  try {
    results = await Promise.all([
      // apkAnalyze(targetImage, apkDbFileContent),
      aptAnalyze(targetImage, aptDbFileContent),
      // rpmAnalyze(targetImage, rpmDbFileContent),
    ]);
  } catch (err) {
    debug(`Could not detect installed OS packages: ${JSON.stringify(err)}`);
    throw new Error("Failed to detect installed OS packages");
  }

  const applicationDependenciesScanResults: AppDepsScanResultWithoutTarget[] = [];

  return {
    imageId: "my/machine",
    osRelease,
    platform: os.arch(),
    results,
    binaries: [],
    imageLayers: [],
    // rootFsLayers: [],
    applicationDependenciesScanResults,
    manifestFiles: [],
    // autoDetectedUserInstructions,
    // imageLabels,
    // imageCreationTime,
  };
}

function getNestedJarsDesiredDepth(options: Partial<PluginOptions>) {
  const nestedJarsOption =
    options["nested-jars-depth"] || options["shaded-jars-depth"];
  let nestedJarsDepth = 1;
  const depthNumber = Number(nestedJarsOption);
  if (!isNaN(depthNumber) && depthNumber >= 0) {
    nestedJarsDepth = depthNumber;
  }
  return nestedJarsDepth;
}

function shouldCheckForGlobs(globsToFind: {
  include: string[];
  exclude: string[];
}): boolean {
  return globsToFind.include.length > 0;
}
