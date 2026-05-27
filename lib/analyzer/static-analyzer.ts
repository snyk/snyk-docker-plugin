import * as Debug from "debug";
import { DockerFileAnalysis } from "../dockerfile";
import { getErrorMessage } from "../error-utils";
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
import { getJavaRuntimeReleaseAction } from "../inputs/base-runtimes/static";
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
import { detectJavaRuntime } from "./base-runtimes";
import {
  checkHistoryAlignment,
  computeOsLayerAttribution,
} from "./layer-attribution";
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
  IntroducingLayerByPackage,
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
    getJavaRuntimeReleaseAction,
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

  const timings: Record<string, number> = {};

  let phaseStart = Date.now();
  const {
    imageId,
    manifestLayers,
    extractedLayers,
    orderedLayers,
    rootFsLayers,
    autoDetectedUserInstructions,
    platform,
    imageLabels,
    imageCreationTime,
    containerConfig,
    history,
  } = await archiveExtractor.extractImageContent(
    imageType,
    imagePath,
    staticAnalysisActions,
    options,
  );
  timings.imageExtractionMs = Date.now() - phaseStart;

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
    debug(`Could not detect OS release: ${getErrorMessage(err)}`);
    throw new Error("Failed to detect OS release");
  }

  const redHatRepositories =
    getRedHatRepositoriesFromExtractedLayers(extractedLayers);

  let results: ImagePackagesAnalysis[];
  try {
    phaseStart = Date.now();
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
    timings.osPackageAnalysisMs = Date.now() - phaseStart;
  } catch (err) {
    debug(`Could not detect installed OS packages: ${getErrorMessage(err)}`);
    throw new Error("Failed to detect installed OS packages");
  }

  let introducingLayerByPackage: IntroducingLayerByPackage | undefined;
  const layerAttributionWarnings: string[] = [];
  if (
    isTrue(options["layer-attribution"]) &&
    rootFsLayers &&
    orderedLayers &&
    orderedLayers.length > 0
  ) {
    phaseStart = Date.now();
    // Surface a user-visible warning when `history` does not align 1:1
    // with `rootfs.diff_ids[]`. The per-package labels we mint below are
    // keyed by diffID and remain correct; the warning only tells the
    // user that downstream joins from diffID to Dockerfile instruction
    // text (performed by the backend at read time) may not work.
    const misalignmentWarning = checkHistoryAlignment(rootFsLayers, history);
    if (misalignmentWarning) {
      layerAttributionWarnings.push(misalignmentWarning);
      debug(misalignmentWarning);
    }
    // `results` carries one entry per DB *format* (e.g. RPM BDB/NDB and RPM
    // SQLite are separate, both `AnalysisType.Rpm`); attribution is keyed on
    // `AnalyzeType` and reads every format for that ecosystem internally.
    // Deduping by ecosystem happens inside the helper.
    if (results.some((r) => r.Analysis.length > 0)) {
      introducingLayerByPackage = await computeOsLayerAttribution(
        results,
        orderedLayers,
        rootFsLayers,
        targetImage,
        osRelease,
        redHatRepositories,
        (analysisType, warning) =>
          debug(
            `Layer attribution warning for ${analysisType}: ${getErrorMessage(
              warning,
            )}`,
          ),
      );
    }
    timings.layerAttributionMs = Date.now() - phaseStart;
  }

  phaseStart = Date.now();
  const binaries = getBinariesHashes(extractedLayers);
  const javaRuntime = detectJavaRuntime(extractedLayers);
  const baseRuntimes = javaRuntime ? [javaRuntime] : undefined;
  timings.binariesAndRuntimeDetectionMs = Date.now() - phaseStart;

  const applicationDependenciesScanResults: AppDepsScanResultWithoutTarget[] =
    [];

  if (appScan) {
    phaseStart = Date.now();
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
    timings.nodeAnalysisMs = Date.now() - phaseStart;

    phaseStart = Date.now();
    const phpDependenciesScanResults = await phpFilesToScannedProjects(
      getFileContent(extractedLayers, getPhpAppFileContentAction.actionName),
    );
    timings.phpAnalysisMs = Date.now() - phaseStart;

    phaseStart = Date.now();
    const poetryDependenciesScanResults = await poetryFilesToScannedProjects(
      getFileContent(extractedLayers, getPoetryAppFileContentAction.actionName),
    );
    timings.poetryAnalysisMs = Date.now() - phaseStart;

    phaseStart = Date.now();
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
    timings.pipAnalysisMs = Date.now() - phaseStart;

    phaseStart = Date.now();
    const desiredLevelsOfUnpacking = getNestedJarsDesiredDepth(options);
    const jarFingerprintScanResults = await jarFilesToScannedResults(
      getBufferContent(extractedLayers, getJarFileContentAction.actionName),
      targetImage,
      desiredLevelsOfUnpacking,
    );
    timings.jarAnalysisMs = Date.now() - phaseStart;

    phaseStart = Date.now();
    const goModulesScanResult = await goModulesToScannedProjects(
      getElfFileContent(extractedLayers, getGoModulesContentAction.actionName),
    );
    timings.goAnalysisMs = Date.now() - phaseStart;

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
    baseRuntimes,
    imageLayers: manifestLayers,
    rootFsLayers,
    introducingLayerByPackage,
    layerAttributionWarnings:
      layerAttributionWarnings.length > 0
        ? layerAttributionWarnings
        : undefined,
    applicationDependenciesScanResults,
    manifestFiles,
    autoDetectedUserInstructions,
    imageLabels,
    imageCreationTime,
    containerConfig,
    history,
    timings,
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
