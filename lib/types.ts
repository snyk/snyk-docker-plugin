export interface StaticAnalysisOptions {
  imagePath: string;
  imageType: ImageType;
  distroless: boolean;
}

export enum ImageType {
  Identifier, // e.g. "nginx:latest"
  DockerArchive = "docker-archive", // e.g. "docker-archive:/tmp/nginx.tar"
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

export interface PluginResponseStatic extends PluginResponse {
  hashes: string[];
}

// NEW STUFF

export interface PluginResponse {
  plugin: PluginMetadata;
  scannedProjects: ScannedProjectCustom[];
}

export interface ScannedProjectCustom {
  packageManager: string; // actually SupportedPackageManagers; in the CLI
  depTree: DepTree;
  targetFile?: string;
  meta?: any;
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

// export type SupportedPackageManagers =
//   | 'rubygems'
//   | 'npm'
//   | 'yarn'
//   | 'maven'
//   | 'pip'
//   | 'sbt'
//   | 'gradle'
//   | 'golangdep'
//   | 'govendor'
//   | 'gomodules'
//   | 'nuget'
//   | 'paket'
//   | 'composer'
//   | 'cocoapods';

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
