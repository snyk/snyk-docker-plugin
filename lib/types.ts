import { DepGraphData } from "@snyk/dep-graph";

import {
  DockerFileAnalysis,
  DockerFileLayers,
  DockerFilePackages,
} from "./dockerfile/types";

export enum ImageType {
  UnspecifiedArchiveType, // "e.g /path/nginx.tar"
  Identifier, // e.g. "nginx:latest"
  DockerArchive = "docker-archive", // e.g. "docker-archive:/tmp/nginx.tar"
  OciArchive = "oci-archive", // e.g. "oci-archive:/tmp/nginx.tar"
  KanikoArchive = "kaniko-archive",
}

export enum OsReleaseFilePath {
  Linux = "/etc/os-release",
  LinuxFallback = "/usr/lib/os-release",
  Lsb = "/etc/lsb-release",
  Debian = "/etc/debian_version",
  Alpine = "/etc/alpine-release",
  RedHat = "/etc/redhat-release",
  Oracle = "/etc/oracle-release",
  Centos = "/etc/centos-release",
}

export enum HashAlgorithm {
  Sha256 = "sha256",
  Sha1 = "sha1",
}

export enum UnresolvedDockerfileVariableHandling {
  Abort = "Abort",
  Continue = "Continue",
}

export interface ManifestFile {
  name: string;
  path: string;
  /**
   * Base64-encoded file contents.
   * We use Base64 to avoid any assumptions about the original file encoding,
   * which is difficult to infer and may be corrupted when the data is transferred over the network.
   */
  contents: string;
}

export interface ImageNameInfo {
  names: string[];
  // this will allow us to extend in the future when needed
}

export type FactType =
  | "autoDetectedUserInstructions"
  | "depGraph"
  | "dockerfileAnalysis"
  | "imageCreationTime"
  | "imageId"
  | "imageLabels"
  // Collects the file names of the individual .tar layers found in the scanned image.
  | "imageLayers"
  // Package manager manifests (e.g. requirements.txt, Gemfile.lock) collected as part of an application scan.
  | "imageManifestFiles"
  | "imageNames"
  | "imageOsReleasePrettyName"
  | "imageSizeBytes"
  // Hashes of extracted *.jar binaries, hashed with sha1 algorithm
  | "jarFingerprints"
  // Hashes of executables not installed by a package manager (e.g. if they were copied straight onto the image).
  | "keyBinariesHashes"
  | "loadedPackages"
  | "ociDistributionMetadata"
  | "rootFs"
  // Used for application dependencies scanning; shows which files were used in the analysis of the dependencies.
  | "testedFiles"
  // Application files observed in the image
  | "applicationFiles";

export interface PluginResponse {
  /** The first result is guaranteed to be the OS dependencies scan result. */
  scanResults: ScanResult[];
}

export interface ScanResult {
  /** User-friendly name to use as the name of the Project that Snyk creates. */
  name?: string;
  /** Contains the Snyk policy file content. */
  policy?: string;
  /** The target defines "where" you found this scan result. */
  target: ContainerTarget;
  /** Identity defines "what" you found. */
  identity: Identity;
  /** Facts are the collection of things you found. */
  facts: Fact[];
  /** A reference for differentiating project versions, e.g., branch names, versions, etc. */
  targetReference?: string;
}

export interface AutoDetectedUserInstructions {
  dockerfilePackages: DockerFilePackages;
  dockerfileLayers: DockerFileLayers;
}

export interface ContainerTarget {
  image: string;
}

/**
 * The identity of a scan result allows to uniquely locate "what" you found.
 * Any differences in the identity influences how a Project is created in Snyk
 * and can result in a completely different Project (for example, if "args.targetFramework" differs).
 */
export interface Identity {
  /**
   * This used to be represented as "packageManager" but now can contain any sensible ecosystem type.
   * Examples: dockerfile, cpp, terraform-module, deb, npm, and so on.
   */
  type: string;
  targetFile?: string;
  args?: { [key: string]: string };
}

/**
 * A collection of things that were found as part of a scan.
 * As the developer and owner, you are responsible for defining and maintaining your own Facts.
 * Examples of facts: a dependency graph, a list of file content hashes, Dockerfile analysis. See FactType.
 */
export interface Fact {
  type: FactType;
  data: any;
}

/**
 * WARNING! WARNING! WARNING!
 * The CLI may pass certain values as strings.
 * Please make sure to sanitize ALL input and not assume it is a "number" or "boolean".
 */
export interface PluginOptions {
  /** This can be an image identifier, or a path to an OCI or Docker archive. */
  path: string;
  /** Override the default plugin path when pulling images to the filesystem. */
  imageSavePath: string;
  /** Path to a Dockerfile. */
  file: string;

  /**
   * Override the "name" and "version" fields of the OS dependencies result.
   * WARNING! This is NOT used by the Snyk CLI!
   *
   * It is used by K8s-Monitor and DRA to preserve the image identifier when scanning archives.
   * The archives do not contain any data about the image's name and tag (since they are only
   * known by the container registry) and in some contexts we know this data and want to keep it.
   *
   * This flag will be processed only when scanning image archives. In other cases "path" is used.
   */
  imageNameAndTag: string;

  /**
   * WARNING! This is NOT used by the Snyk CLI!
   *
   * It is used by K8s-Monitor to preserve the imageNameAndDigest if we can extract this
   * information from the workload metadata when scanning archives.
   */
  imageNameAndDigest: string;

  /**
   * WARNING! This is NOT used by the Snyk CLI!
   *
   * It is used by Docker Registry Agent to preserve the image digests if we can extract this
   * information from pulling the image with Snyk Docker Pull.
   */
  digests: { manifest?: string; index?: string };

  /**
   * Provide patterns on which to match for detecting package manager manifest files.
   * Used for the APP+OS deps feature, not by the CLI.
   */
  globsToFind: {
    include: string[];
    exclude: string[];
  };

  /** For authentication to a container registry. */
  username: string;
  /** For authentication to a container registry. */
  password: string;

  /**
   * Format is "operating-system/processor-architecture", for example "linux/arm64/v8".
   * The default is "linux/amd64".
   */
  platform: string;

  /**
   * Whether to enable application dependencies scanning.
   * It's here so that things don't completely break if used, but it should not be used
   * (and is ignored) starting with release version 5.0.0
   */
  "app-vulns": boolean | string;

  /** Whether to disable application dependencies scanning. The default is "false" */
  "exclude-app-vulns": boolean | string;
  /** Whether to disable node modules dependencies scanning. The default is "false" */
  "exclude-node-modules": boolean | string;
  /**
   * How many levels of (nested) JARs we should unpack
   * If a JAR contains other JARs (AKA JAR of JARs), we send back only the children JARs, and don't look for vulns in the parent.
   *
   * If the flag was not provided but --app-vuls was, we unpack 1 level.
   * If 0 is provided, we do not unpack any JARs
   * if n > 0 is provided, we try to unpack n levels of JARs.
   * The default (if flag is provided, but without a number) is 1 level
   *
   * Cannot come with exclude-app-vulns
   *
   * Alias: shaded-jars-depth
   * TODO remove shaded-jars-depth
   * A shaded JAR is when you unpack all JAR files, then repack them into a single JAR, while
   * renaming (i.e., "shading") all packages of all dependencies.
   */
  "nested-jars-depth": boolean | string;
  "shaded-jars-depth": boolean | string;

  /** The default is "false". */
  "exclude-base-image-vulns": boolean | string;

  /** The default is "false". */
  "collect-application-files": boolean | string;
  "target-reference": string;
}

export interface DepTreeDep {
  name: string;
  version: string;
  sourceVersion?: string;
  dependencies: {
    [depName: string]: DepTreeDep;
  };
  purl?: string;
  labels?: {
    [key: string]: string;
  };
}

/** @deprecated Prefer building Graphs instead of Trees. */
export interface DepTree extends DepTreeDep {
  type?: string;
  packageFormatVersion: string;
  targetOS: {
    name: string;
    prettyName: string;
    version: string;
  };

  targetFile?: string;
  policy?: string;
  docker?: {
    dockerfileAnalysis?: DockerFileAnalysis;
    dockerfilePkgs?: DockerFilePackages;
    dockerImageId?: string;
    imageLayers?: string[];
    rootFs?: string[];
    imageName?: string;
  };
  files?: any;
}

export interface Issue {
  pkgName: string;
  pkgVersion?: string;
  issueId: string;
  fixInfo: {
    nearestFixedInVersion?: string; // TODO: add more fix info
  };
}

export interface IssuesData {
  [issueId: string]: {
    id: string;
    severity: string;
    from: string[][];
    title: string;
  };
}

export interface BaseImageRemediationAdvice {
  message: string;
  bold?: boolean;
  color?: string;
}

interface BaseImageRemediation {
  code: string;
  advice: BaseImageRemediationAdvice[];
  message?: string; // TODO: check if this is still being sent
}

export interface TestResult {
  org: string;
  licensesPolicy: object | null;
  docker: {
    baseImage?: string;
    baseImageRemediation?: BaseImageRemediation;
  };
  issues: Issue[];
  issuesData: IssuesData;
  depGraphData: DepGraphData;
}

export interface Options {
  path: string;
  file?: string;
  debug?: boolean;
  isDockerUser?: boolean;
  config?: any;
}
