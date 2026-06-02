import { goScanner } from "../../go-parser";
import { jarScanner } from "./java";
import { nodeApplicationFilesScanner, nodeScanner } from "./node";
import { phpScanner } from "./php";
import {
  pipScanner,
  poetryScanner,
  pythonApplicationFilesScanner,
} from "./python";
import { EcosystemScanner } from "./types";

/**
 * Ordered registry of application ecosystem scanners. The order is a
 * load-bearing contract: it determines the order of `applicationDependenciesScanResults`
 * (and therefore `PluginResponse.scanResults`), which consumers index positionally.
 */
export const applicationScanners: EcosystemScanner[] = [
  nodeScanner,
  nodeApplicationFilesScanner,
  phpScanner,
  poetryScanner,
  pipScanner,
  pythonApplicationFilesScanner,
  jarScanner,
  goScanner,
];
