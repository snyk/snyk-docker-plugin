import * as Debug from "debug";
import { DockerFileAnalysis } from "../dockerfile";
import * as archiveExtractor from "../extractor";
import {
  getGoModulesContentAction,
  goModulesToScannedProjects,
} from "../go-parser";
import { getBufferContent, getElfFileContent, getFileContent } from "../inputs";
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
import * as filePatternStatic from "../inputs/file-pattern/static";
import { getJarFileContentAction } from "../inputs/java/static";
import { getNodeAppFileContentAction } from "../inputs/node/static";
import { getOsReleaseActions } from "../inputs/os-release/static";
import { getPhpAppFileContentAction } from "../inputs/php/static";
import {
  getPipAppFileContentAction,
  getPoetryAppFileContentAction,
} from "../inputs/python/static";
import {
  getRedHatRepositoriesContentAction,
  getRedHatRepositoriesFromExtractedLayers,
} from "../inputs/redHat/static";
import {
  getRpmDbFileContent,
  getRpmDbFileContentAction,
  getRpmSqliteDbFileContent,
  getRpmSqliteDbFileContentAction,
} from "../inputs/rpm/static";
import { isTrue } from "../option-utils";
import { ImageType, ManifestFile, PluginOptions } from "../types";
import {
  nodeFilesToScannedProjects,
  phpFilesToScannedProjects,
  poetryFilesToScannedProjects,
} from "./applications";
import { jarFilesToScannedResults } from "./applications/java";
import { pipFilesToScannedProjects } from "./applications/python";
import { AppDepsScanResultWithoutTarget } from "./applications/types";
import * as osReleaseDetector from "./os-release";
import { analyze as apkAnalyze } from "./package-managers/apk";
import {
  analyze as aptAnalyze,
  analyzeDistroless as aptDistrolessAnalyze,
} from "./package-managers/apt";
import {
  analyze as rpmAnalyze,
  mapRpmSqlitePackages,
} from "./package-managers/rpm";
import {
  ImagePackagesAnalysis,
  OSRelease,
  StaticPackagesAnalysis,
} from "./types";

const debug = Debug("snyk");

export async function analyze(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  imageType: ImageType,
  imagePath: string,
  globsToFind: { include: string[]; exclude: string[] },
  options: Partial<PluginOptions>,
): Promise<StaticPackagesAnalysis> {
  const staticAnalysisActions = [
    getApkDbFileContentAction,
    getDpkgFileContentAction,
    getExtFileContentAction,
    getRpmDbFileContentAction,
    getRpmSqliteDbFileContentAction,
    ...getOsReleaseActions,
    getNodeBinariesFileContentAction,
    getOpenJDKBinariesFileContentAction,
    getDpkgPackageFileContentAction,
    getRedHatRepositoriesContentAction,
  ];

  const checkForGlobs = shouldCheckForGlobs(globsToFind);
  if (checkForGlobs) {
    staticAnalysisActions.push(
      filePatternStatic.generateExtractAction(
        globsToFind.include,
        globsToFind.exclude,
      ),
    );
  }

  const appScan = !isTrue(options["exclude-app-vulns"]);

  if (appScan) {
    staticAnalysisActions.push(
      ...[
        getNodeAppFileContentAction,
        getPhpAppFileContentAction,
        getPoetryAppFileContentAction,
        getPipAppFileContentAction,
        getJarFileContentAction,
        getGoModulesContentAction,
      ],
    );
  }

  const {
    imageId,
    manifestLayers,
    extractedLayers,
    rootFsLayers,
    autoDetectedUserInstructions,
    platform,
    imageLabels,
    imageCreationTime,
  } = await archiveExtractor.extractImageContent(
    imageType,
    imagePath,
    staticAnalysisActions,
  );

  const [
    apkDbFileContent,
    aptDbFileContent,
    rpmDbFileContent,
    rpmSqliteDbFileContent,
  ] = await Promise.all([
    getApkDbFileContent(extractedLayers),
    getAptDbFileContent(extractedLayers),
    getRpmDbFileContent(extractedLayers),
    getRpmSqliteDbFileContent(extractedLayers),
  ]);

  const distrolessAptFiles = getAptFiles(extractedLayers);

  const manifestFiles: ManifestFile[] = [];
  if (checkForGlobs) {
    const matchingFiles = filePatternStatic.getMatchingFiles(extractedLayers);
    manifestFiles.push(...matchingFiles);
  }

  let osRelease: OSRelease;
  try {
    osRelease = await osReleaseDetector.detectStatically(
      extractedLayers,
      dockerfileAnalysis,
    );
  } catch (err) {
    debug(`Could not detect OS release: ${JSON.stringify(err)}`);
    throw new Error("Failed to detect OS release");
  }

  let results: ImagePackagesAnalysis[];
  try {
    results = await Promise.all([
      apkAnalyze(targetImage, apkDbFileContent),
      aptAnalyze(targetImage, aptDbFileContent),
      rpmAnalyze(targetImage, rpmDbFileContent),
      mapRpmSqlitePackages(targetImage, rpmSqliteDbFileContent),
      aptDistrolessAnalyze(targetImage, distrolessAptFiles),
    ]);
  } catch (err) {
    debug(`Could not detect installed OS packages: ${JSON.stringify(err)}`);
    throw new Error("Failed to detect installed OS packages");
  }

  const binaries = getBinariesHashes(extractedLayers);

  const redHatRepositories =
    getRedHatRepositoriesFromExtractedLayers(extractedLayers);

  const applicationDependenciesScanResults: AppDepsScanResultWithoutTarget[] =
    [];

  if (appScan) {
    const nodeDependenciesScanResults = await nodeFilesToScannedProjects(
      getFileContent(extractedLayers, getNodeAppFileContentAction.actionName),
    );
    const phpDependenciesScanResults = await phpFilesToScannedProjects(
      getFileContent(extractedLayers, getPhpAppFileContentAction.actionName),
    );
    const poetryDependenciesScanResults = await poetryFilesToScannedProjects(
      getFileContent(extractedLayers, getPoetryAppFileContentAction.actionName),
    );

    const pipDependenciesScanResults = await pipFilesToScannedProjects(
      getFileContent(extractedLayers, getPipAppFileContentAction.actionName),
    );

    const desiredLevelsOfUnpacking = getNestedJarsDesiredDepth(options);

    const jarFingerprintScanResults = await jarFilesToScannedResults(
      getBufferContent(extractedLayers, getJarFileContentAction.actionName),
      targetImage,
      desiredLevelsOfUnpacking,
    );
    const goModulesScanResult = await goModulesToScannedProjects(
      getElfFileContent(extractedLayers, getGoModulesContentAction.actionName),
    );

    applicationDependenciesScanResults.push(
      ...nodeDependenciesScanResults,
      ...phpDependenciesScanResults,
      ...poetryDependenciesScanResults,
      ...pipDependenciesScanResults,
      ...jarFingerprintScanResults,
      ...goModulesScanResult,
    );
  }

  return {
    imageId,
    osRelease,
    platform,
    results,
    binaries,
    imageLayers: manifestLayers,
    rootFsLayers,
    applicationDependenciesScanResults,
    manifestFiles,
    autoDetectedUserInstructions,
    imageLabels,
    imageCreationTime,
    redHatRepositories,
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
