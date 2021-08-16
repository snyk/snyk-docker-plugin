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
export interface JarBuffer {
  location: string;
  digest: Buffer;
}

export interface FilePathToElfContent {
  [filePath: string]: Elf;
}
