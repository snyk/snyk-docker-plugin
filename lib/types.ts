export interface StaticAnalysisOptions {
  imagePath: string;
  imageType: ImageType;
  distroless: boolean;
}

export enum ImageTransport {
  ContainerRegistry,
  DockerArchive,
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
  package: Package;
  manifestFiles: ManifestFile[];
}

export interface PluginResponseStatic extends PluginResponse {
  hashes: string[];
}
