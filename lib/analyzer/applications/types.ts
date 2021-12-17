import { Elf } from "../../go-parser/types";
import { ScanResult } from "../../types";

export interface AppDepsScanResultWithoutTarget
  extends Omit<ScanResult, "target"> {}

export interface FilePathToContent {
  [filePath: string]: string;
}
export interface FilePathToBuffer {
  [filePath: string]: Buffer;
}

export interface JarTraverseResults {
  unpackedLevels: number;
  scannedFiles: number;
  jarBuffer: JarBuffer[];
}
export interface JarBuffer {
  location: string;
  digest: Buffer;
  dependencies: JarDep[];
}
export interface JarDep {
  parentName?: string;
  name?: string;
  version?: string;
}

export interface PomProperties {
  groupId?: string;
  artifactId?: string;
  version?: string;
}

export interface FilePathToElfContent {
  [filePath: string]: Elf;
}
