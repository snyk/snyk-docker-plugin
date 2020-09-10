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

export interface Artifact {
  type: string;
  data: any;
  meta: { [key: string]: any };
}

export interface ScanResult {
  artifacts: Artifact[];
  meta: {
    [key: string]: any;
  };
}
export interface OsDepsScanResult extends ScanResult {
  meta: {
    dockerfileAnalysis?: DockerFileAnalysis;
    dockerfilePkgs?: DockerFilePackages;
    dockerImageId?: string;
    imageLayers?: string[];
    rootFs?: string[];
    /** Groups related scan results together in Snyk (as a project grouping). */
    imageName?: string;
  };
}

export interface AppDepsScanResult extends ScanResult {
  meta: {
    targetFile?: string;
    /** Groups related scan results together in Snyk (as a project grouping). */
    imageName?: string;
  };
}

export interface ScanOptions {
  imagePath: string;
  imageSavePath: string;
  imageType: ImageType;
  experimental: boolean;
  appScan: boolean;
  "app-vulns": boolean;
  globsToFind: {
    include: string[];
    exclude: string[];
  };
  username: string;
  password: string;
  platform: string;
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
