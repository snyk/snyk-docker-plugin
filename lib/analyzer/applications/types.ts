import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { Elf } from "../../go-parser/types";
import { ScanResult } from "../../types";

export interface AppDepsScanResultWithoutTarget
  extends Omit<ScanResult, "target"> {}

/**
 * Fully-derived inputs an {@link EcosystemScanner} needs. Built once by the
 * orchestrator from the raw plugin options; scanners never see the options bag.
 */
export interface ScanContext {
  targetImage: string;
  nodeModulesScan: boolean;
  collectApplicationFiles: boolean;
  includeSystemJars: boolean;
  nestedJarsDepth: number;
}

/**
 * A single application ecosystem's contribution to a static scan: the extract
 * actions it needs registered before image extraction, and the scan that turns
 * the extracted layers into dependency scan results. Registered in execution
 * order in `scanners.ts`.
 */
export interface EcosystemScanner {
  name: string;
  // Analytics contract key under which this scanner's timing is accumulated.
  timingKey: string;
  isEnabled(ctx: ScanContext): boolean;
  actions(ctx: ScanContext): ExtractAction[];
  scan(
    extractedLayers: ExtractedLayers,
    ctx: ScanContext,
  ): Promise<AppDepsScanResultWithoutTarget[]>;
}

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
}

export type FilesByDirMap = Map<string, Set<string>>;
