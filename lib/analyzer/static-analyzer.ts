import * as Debug from "debug";
import { DockerFileAnalysis } from "../dockerfile";
import { getErrorMessage } from "../error-utils";
import * as archiveExtractor from "../extractor";
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
import { getOsReleaseActions } from "../inputs/os-release/static";
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
import { applicationScanners } from "./applications/scanners";
import {
  AppDepsScanResultWithoutTarget,
  ScanContext,
} from "./applications/types";
import { detectJavaRuntime } from "./base-runtimes";
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

  const scanContext: ScanContext = {
    targetImage,
    nodeModulesScan: !isTrue(options["exclude-node-modules"]),
    // A runtime logic enabler flag. Is off by default.
    collectApplicationFiles: isTrue(options["collect-application-files"]),
    includeSystemJars: isTrue(options["include-system-jars"]),
    nestedJarsDepth: getNestedJarsDesiredDepth(options),
  };

  if (appScan) {
    for (const scanner of applicationScanners) {
      if (scanner.isEnabled(scanContext)) {
        staticAnalysisActions.push(...scanner.actions(scanContext));
      }
    }
  }

  const timings: Record<string, number> = {};

  let phaseStart = Date.now();
  const {
    imageId,
    manifestLayers,
    extractedLayers,
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

  phaseStart = Date.now();
  const binaries = getBinariesHashes(extractedLayers);
  const javaRuntime = detectJavaRuntime(extractedLayers);
  const baseRuntimes = javaRuntime ? [javaRuntime] : undefined;
  timings.binariesAndRuntimeDetectionMs = Date.now() - phaseStart;

  const applicationDependenciesScanResults: AppDepsScanResultWithoutTarget[] =
    [];

  if (appScan) {
    for (const scanner of applicationScanners) {
      if (!scanner.isEnabled(scanContext)) {
        continue;
      }
      phaseStart = Date.now();
      const scanResults = await scanner.scan(extractedLayers, scanContext);
      timings[scanner.timingKey] =
        (timings[scanner.timingKey] || 0) + (Date.now() - phaseStart);
      applicationDependenciesScanResults.push(...scanResults);
    }
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
