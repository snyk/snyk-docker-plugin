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
  getChiselManifestAction,
  getChiselManifestContent,
} from "../inputs/chisel/static";
import {
  getAptFiles,
  getDpkgPackageFileContentAction,
} from "../inputs/distroless/static";
import * as filePatternStatic from "../inputs/file-pattern/static";
import {
  getJarFileContentAction,
  getUsrLibJarFileContentAction,
} from "../inputs/java/static";
import {
  getNodeAppFileContentAction,
  getNodeJsTsAppFileContentAction,
} from "../inputs/node/static";
import { getOsReleaseActions } from "../inputs/os-release/static";
import { getPhpAppFileContentAction } from "../inputs/php/static";
import {
  getPipAppFileContentAction,
  getPoetryAppFileContentAction,
  getPythonAppFileContentAction,
} from "../inputs/python/static";
import {
  getRedHatRepositoriesContentAction,
  getRedHatRepositoriesFromExtractedLayers,
} from "../inputs/redHat/static";
import {
  getRpmDbFileContent,
  getRpmDbFileContentAction,
  getRpmNdbFileContent,
  getRpmNdbFileContentAction,
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
import { getApplicationFiles } from "./applications/runtime-common";
import { AppDepsScanResultWithoutTarget } from "./applications/types";
import * as osReleaseDetector from "./os-release";
import { analyze as apkAnalyze } from "./package-managers/apk";
import {
  analyze as aptAnalyze,
  analyzeDistroless as aptDistrolessAnalyze,
} from "./package-managers/apt";
import { analyze as chiselAnalyze } from "./package-managers/chisel";
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
    getRpmNdbFileContentAction,
    getChiselManifestAction,
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
  const nodeModulesScan = !isTrue(options["exclude-node-modules"]);
  // A runtime logic enabler flag. Is off by default.
  const collectApplicationFiles = isTrue(options["collect-application-files"]);

  if (appScan) {
    const jarActions = [getJarFileContentAction];

    // Include system JARs from /usr/lib if flag is enabled
    if (isTrue(options["include-system-jars"])) {
      jarActions.push(getUsrLibJarFileContentAction);
    }

    staticAnalysisActions.push(
      ...[
        getNodeAppFileContentAction,
        getPhpAppFileContentAction,
        getPoetryAppFileContentAction,
        getPipAppFileContentAction,
        ...jarActions,
        getGoModulesContentAction,
      ],
    );

    if (collectApplicationFiles) {
      staticAnalysisActions.push(
        getNodeJsTsAppFileContentAction,
        getPythonAppFileContentAction,
      );
    }
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
    options,
  );

  const [
    apkDbFileContent,
    aptDbFileContent,
    rpmDbFileContent,
    rpmSqliteDbFileContent,
    rpmNdbFileContent,
    chiselPackages,
  ] = await Promise.all([
    getApkDbFileContent(extractedLayers),
    getAptDbFileContent(extractedLayers),
    getRpmDbFileContent(extractedLayers),
    getRpmSqliteDbFileContent(extractedLayers),
    getRpmNdbFileContent(extractedLayers),
    getChiselManifestContent(extractedLayers),
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
    debug(`Could not detect OS release: ${err.message}`);
    throw new Error("Failed to detect OS release");
  }

  const redHatRepositories =
    getRedHatRepositoriesFromExtractedLayers(extractedLayers);

  let results: ImagePackagesAnalysis[];
  try {
    results = await Promise.all([
      apkAnalyze(targetImage, apkDbFileContent),
      aptAnalyze(targetImage, aptDbFileContent, osRelease),
      rpmAnalyze(
        targetImage,
        [...rpmDbFileContent, ...rpmNdbFileContent],
        redHatRepositories,
        osRelease,
      ),
      mapRpmSqlitePackages(
        targetImage,
        rpmSqliteDbFileContent,
        redHatRepositories,
        osRelease,
      ),
      aptDistrolessAnalyze(targetImage, distrolessAptFiles, osRelease),
      chiselAnalyze(targetImage, chiselPackages),
    ]);
  } catch (err) {
    debug(`Could not detect installed OS packages: ${err.message}`);
    throw new Error("Failed to detect installed OS packages");
  }

  const binaries = getBinariesHashes(extractedLayers);

  const applicationDependenciesScanResults: AppDepsScanResultWithoutTarget[] =
    [];

  if (appScan) {
    const nodeDependenciesScanResults = await nodeFilesToScannedProjects(
      getFileContent(extractedLayers, getNodeAppFileContentAction.actionName),
      nodeModulesScan,
    );
    let nodeApplicationFilesScanResults: AppDepsScanResultWithoutTarget[] = [];
    if (collectApplicationFiles) {
      nodeApplicationFilesScanResults = getApplicationFiles(
        getFileContent(
          extractedLayers,
          getNodeJsTsAppFileContentAction.actionName,
        ),
        "node",
        "npm",
      );
    }

    const phpDependenciesScanResults = await phpFilesToScannedProjects(
      getFileContent(extractedLayers, getPhpAppFileContentAction.actionName),
    );

    const poetryDependenciesScanResults = await poetryFilesToScannedProjects(
      getFileContent(extractedLayers, getPoetryAppFileContentAction.actionName),
    );

    const pipDependenciesScanResults = await pipFilesToScannedProjects(
      getFileContent(extractedLayers, getPipAppFileContentAction.actionName),
    );

    let pythonApplicationFilesScanResults: AppDepsScanResultWithoutTarget[] =
      [];
    if (collectApplicationFiles) {
      pythonApplicationFilesScanResults = getApplicationFiles(
        getFileContent(
          extractedLayers,
          getPythonAppFileContentAction.actionName,
        ),
        "python",
        "python",
      );
    }

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
      ...nodeApplicationFilesScanResults,
      ...phpDependenciesScanResults,
      ...poetryDependenciesScanResults,
      ...pipDependenciesScanResults,
      ...pythonApplicationFilesScanResults,
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
