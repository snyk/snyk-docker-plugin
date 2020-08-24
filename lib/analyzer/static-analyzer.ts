import * as Debug from "debug";
import { DockerFileAnalysis } from "../docker-file";
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
import {
  getNodeAppFileContent,
  getNodeAppFileContentAction,
} from "../inputs/node/static";
import { getOsReleaseActions } from "../inputs/os-release/static";
import {
  getRpmDbFileContent,
  getRpmDbFileContentAction,
} from "../inputs/rpm/static";
import {
  ImageType,
  ManifestFile,
  ScannedProjectCustom,
  StaticAnalysisOptions,
} from "../types";
import { nodeFilesToScannedProjects } from "./applications";
import * as osReleaseDetector from "./os-release";
import { analyze as apkAnalyze } from "./package-managers/apk";
import {
  analyze as aptAnalyze,
  analyzeDistroless as aptDistrolessAnalyze,
} from "./package-managers/apt";
import { analyze as rpmAnalyze } from "./package-managers/rpm";
import { ImageAnalysis, OSRelease, StaticAnalysis } from "./types";

const debug = Debug("snyk");

const supportedArchives: ImageType[] = [
  ImageType.DockerArchive,
  ImageType.OciArchive,
];

export async function analyze(
  targetImage: string,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
  options: StaticAnalysisOptions,
): Promise<StaticAnalysis> {
  if (!supportedArchives.includes(options.imageType)) {
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

  const checkForGlobs = shouldCheckForGlobs(options);
  if (checkForGlobs) {
    staticAnalysisActions.push(
      filePatternStatic.generateExtractAction(
        options.globsToFind.include,
        options.globsToFind.exclude,
      ),
    );
  }

  const {
    imageId,
    manifestLayers,
    extractedLayers,
    rootFsLayers,
  } = await archiveExtractor.getArchiveLayersAndManifest(
    options.imageType,
    options.imagePath,
    staticAnalysisActions,
  );

  const [
    apkDbFileContent,
    aptDbFileContent,
    rpmDbFileContent,
  ] = await Promise.all([
    getApkDbFileContent(extractedLayers),
    getAptDbFileContent(extractedLayers),
    getRpmDbFileContent(extractedLayers),
  ]);

  let distrolessAptFiles: string[] = [];
  if (options.distroless) {
    distrolessAptFiles = getAptFiles(extractedLayers);
  }

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

  const binaries = getBinariesHashes(extractedLayers);

  const applicationDependenciesScanResults: ScannedProjectCustom[] = [];
  if (options.appScan) {
    const nodeDependenciesScanResults = await nodeFilesToScannedProjects(
      getNodeAppFileContent(extractedLayers),
    );
    applicationDependenciesScanResults.push(...nodeDependenciesScanResults);
  }
  return {
    imageId,
    osRelease,
    results,
    binaries,
    imageLayers: manifestLayers,
    rootFsLayers,
    applicationDependenciesScanResults,
    manifestFiles,
  };
}

function shouldCheckForGlobs(options: StaticAnalysisOptions): boolean {
  return (
    options &&
    options.globsToFind &&
    options.globsToFind.include &&
    Array.isArray(options.globsToFind.include) &&
    options.globsToFind.include.length > 0
  );
}
