export interface StaticAnalysisOptions {
  imagePath: string;
  imageType: ImageType;
  distroless: boolean;
}

export enum ImageType {
  DockerArchive = "docker-archive",
}

export enum OsReleaseFilePath {
  Linux = "/etc/os-release",
  LinuxFallback = "/usr/lib/os-release",
  Lsb = "/etc/lsb-release",
  Debian = "/etc/debian_version",
  Alpine = "/etc/alpine-release",
  RedHat = "/etc/redhat-release",
  Oracle = "/etc/oracle-release",
}

export interface ManifestFile {
  name: string;
  path: string;
  contents: string;
}

export interface PluginMetadata {
  name: string;
  runtime: string | undefined;
  packageManager: any;
  dockerImageId: string;
  imageLayers: string[];
}

// should be renamed and organised
export interface Package {
  dependencies: {
    [key: string]: any; // TODO
  };
  docker: {
    [key: string]: any; // TODO
  };
  name: string;
  packageFormatVersion: string;
  targetOS: {
    name: string;
    prettyName: string;
    version: string;
  };
  version: string;
}

export interface PluginResponse {
  plugin: PluginMetadata;
  package: Package; // under deprecation, Package is one type of scanResult
  scanResults: MultiProjectResultCustom; // to replace package
  manifestFiles: ManifestFile[];
}

export interface PluginResponseStatic extends PluginResponse {
  hashes: string[];
}

// NEW STUFF

export interface MultiProjectResultCustom extends MultiProjectResult {
  scannedProjects: ScannedProjectCustom[];
}

export interface MultiProjectResult {
  plugin: PluginMetadata;
  scannedProjects: ScannedProject[];
}

export interface ScannedProjectCustom extends ScannedProject {
  packageManager: SupportedPackageManagers;
  plugin: PluginMetadata;
  // callGraph?: CallGraph;
}

export interface ScannedProject {
  depTree: DepTree;
  targetFile?: string;
  meta?: any;
  // callGraph?: CallGraph;
}

export interface DepTreeDep {
  name?: string; // shouldn't, but might be missing
  version?: string; // shouldn't, but might be missing
  dependencies?: {
    [depName: string]: DepTreeDep,
  };
  labels?: {
    [key: string]: string;

    // Known keys:
    // pruned: identical subtree already presents in the parent node.
    //         See --prune-repeated-subdependencies flag.
  };
}

export interface DepTree extends DepTreeDep {
  type?: string;
  packageFormatVersion?: string;
  targetOS?: {
    name: string;
    version: string;
  };

  // TODO: clarify which of these extra files are actually needed
  targetFile?: string;
  policy?: string;
  docker?: any;
  files?: any;
}

export type SupportedPackageManagers =
  | 'rubygems'
  | 'npm'
  | 'yarn'
  | 'maven'
  | 'pip'
  | 'sbt'
  | 'gradle'
  | 'golangdep'
  | 'govendor'
  | 'gomodules'
  | 'nuget'
  | 'paket'
  | 'composer'
  | 'cocoapods';

// just for reference
// export interface PluginMetadata {
//   name: string;
//   runtime?: string;
//   targetFile?: string;

//   packageManager?: SupportedPackageManagers;

//   // Per-plugin custom metadata
//   meta?: {
//     allSubProjectNames?: string[],
//     versionBuildInfo?: VersionBuildInfo,
//   };

//   // Docker-related fields
//   dockerImageId?: any;
//   imageLayers?: any;
//   packageFormatVersion?: string;
// }