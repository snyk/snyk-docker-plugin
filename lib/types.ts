import { DepGraphData } from "@snyk/dep-graph";
// test
import { DockerFileAnalysis } from "./docker-file";
import { DockerFilePackages } from "./instruction-parser";

export enum ImageType {
  Identifier, // e.g. "nginx:latest"
  DockerArchive = "docker-archive", // e.g. "docker-archive:/tmp/nginx.tar"
  OciArchive = "oci-archive", // e.g. "oci-archive:/tmp/nginx.tar"
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

export interface ManifestFile {
  name: string;
  path: string;
  contents: Buffer;
}

export type FactType =
  | "depGraph"
  | "keyBinariesHashes"
  | "imageLayers"
  | "dockerfileAnalysis"
  | "rootFs"
  | "imageId"
  | "imageOsReleasePrettyName";

export interface PluginResponse {
  /** The first result is guaranteed to be the OS dependencies scan result. */
  scanResults: ScanResult[];

  /**
   * WARNING: This field does not appear in other CLI plugins! NOT to be used by the CLI.
   *
   * Manifests file are a special case, used only for the APP+OS deps feature.
   * They are collected if "globsToFind" are included in the options passed to the plugin.
   * They are NOT be processed like a normal ScanResult+Fact and they flow through a separate code path.
   */
  manifestFiles?: ManifestFile[];
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
  /** This used to be represented as "packageManager". It becomes the project.type. */
  type: string;
  targetFile?: string;
  args?: { [key: string]: string };
}

/**
 * A collection of things that were found as part of a scan.
 * As the developer and owner, you are responsible for defining and maintaining your own Facts.
 * Examples of facts: a dependency graph, a list of file content hashes, Dockerfile analysis.
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
   * Provide patterns on which to match for detecting applications.
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

  /** Whether to enable application dependencies scanning. The default is "false" */
  "app-vulns": boolean | string;
  /** The default is "false". */
  "exclude-base-image-vulns": boolean | string;
}

export interface DepTreeDep {
  name: string;
  version: string;
  dependencies: {
    [depName: string]: DepTreeDep;
  };
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
