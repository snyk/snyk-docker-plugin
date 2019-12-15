export interface StaticAnalysisOptions {
  imagePath: string;
  imageType: ImageType;
  /**
   * Provide a path to a directory where the plugin can write temporary files.
   * If unspecified, defaults to the environment's temporary directory path.
   */
  tmpDirPath?: string;
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
