import { DepGraphData } from "@snyk/dep-graph";
import { PkgTree } from "snyk-nodejs-lockfile-parser";

export interface StaticAnalysisOptions {
  imagePath: string;
  imageType: ImageType;
  distroless: boolean;
  appScan: boolean;
  globsToFind: {
    include: string[];
    exclude: string[];
  };
}

export enum ImageType {
  Identifier, // e.g. "nginx:latest"
  DockerArchive = "docker-archive", // e.g. "docker-archive:/tmp/nginx.tar"
  OciArchive = "oci-archive",
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

export interface PluginMetadata {
  name: string;
  runtime: string | undefined;
  packageManager: any;
  dockerImageId: string;
  imageLayers: string[];
  rootFs?: string[];
}

export interface PluginResponseStatic extends PluginResponse {
  hashes: string[];
}

export interface PluginResponse {
  plugin: PluginMetadata;
  scannedProjects: ScannedProjectCustom[];
}

export interface ScannedProjectCustom {
  packageManager: string; // actually SupportedPackageManagers; in the CLI
  /**
   * Using "| PkgTree" here to be truthful to the type system.
   * For application dependencies scans we use a parser which has more optional fields than the DepTree.
   * We have different required and optional fields for OS scans and application dependencies scans, so
   * a future change should be mindful but find a way to unify them if possible.
   */
  depTree: DepTree | PkgTree;
  targetFile?: string; // currently used for application-dependencies scans
  meta?: any; // not to pollute with actual data; reserved for actual metadata
}

export enum ScanType {
  DependencyTree = "DependencyTree",
  DependencyGraph = "DependencyGraph",
  ManifestFiles = "ManifestFiles",
}

export interface ScannedProjectExtended extends ScannedProjectCustom {
  scanType: ScanType;
  // unknowingly structured data; determined by `scanType`
  data: unknown;
}

export interface ScannedProjectManifestFiles extends ScannedProjectExtended {
  scanType: ScanType.ManifestFiles;
  data: ManifestFile[];
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
  docker: {
    [key: string]: any; // TODO
  };
  files?: any;
}
export interface GitTarget {
  remoteUrl: string;
  branch: string;
}

export interface ContainerTarget {
  image: string;
}

export interface ScanResult {
  identity: Identity;
  target: GitTarget | ContainerTarget;
  facts: Facts[];
}
export interface Identity {
  type: string; // ex-packageManager, becomes project.type
  targetFile?: string;
  args?: { [key: string]: string };
}
export interface Facts {
  type: string;
  data: any;
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
