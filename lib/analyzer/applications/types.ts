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

export interface JarInfo extends JarBuffer {
  coords: JarCoords | null;
  dependencies: JarCoords[];
  nestedJars: JarBuffer[];
}
export interface JarBuffer {
  location: string;
  buffer: Buffer;
}
export interface JarCoords {
  artifactId?: string;
  groupId?: string;
  version?: string;
}
export interface FilePathToElfContent {
  [filePath: string]: Elf;
}
export interface AggregatedJars {
  [path: string]: JarBuffer[];
}
export interface ApplicationFileInfo {
  path: string;
}
export interface ApplicationFiles {
  fileHierarchy: ApplicationFileInfo[];
  moduleName?: string;
  language: string;
  minimized: boolean;
}

export type FilesByDirMap = Map<string, Set<string>>;
