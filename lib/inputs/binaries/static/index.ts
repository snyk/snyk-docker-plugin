import { ExtractAction, ExtractedLayers } from "../../../extractor/types";
import {
  HASH_ALGORITHM_SHA1,
  HASH_ALGORITHM_SHA256,
  streamToHashSHA1,
  streamToHashSHA256,
} from "../../../stream-utils";
import { BinaryFileData } from "../../../types";

export const getJarBinariesFileContentAction: ExtractAction = {
  actionName: "jar",
  fileNamePattern: "**/*.jar",
  callback: streamToHashSHA1,
  hashType: HASH_ALGORITHM_SHA1,
};

export const getOpenJDKBinariesFileContentAction: ExtractAction = {
  actionName: "java",
  fileNamePattern: "**/java",
  callback: streamToHashSHA256,
  hashType: HASH_ALGORITHM_SHA256,
};

export const getNodeBinariesFileContentAction: ExtractAction = {
  actionName: "node",
  fileNamePattern: "**/node",
  callback: streamToHashSHA256,
  hashType: HASH_ALGORITHM_SHA256,
};

const binariesExtractActions = [
  getNodeBinariesFileContentAction,
  getOpenJDKBinariesFileContentAction,
  getJarBinariesFileContentAction,
];

export function getBinariesHashes(
  extractedLayers: ExtractedLayers,
): BinaryFileData[] {
  const res: BinaryFileData[] = [];
  const hashes: Set<string> = new Set<string>();

  for (const fileName of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[fileName])) {
      for (const action of binariesExtractActions) {
        if (actionName !== action.actionName) {
          continue;
        }

        if (!(typeof extractedLayers[fileName][actionName] === "string")) {
          throw new Error("expected string");
        }

        const hash = extractedLayers[fileName][actionName] as string;

        if (!hashes.has(hash)) {
          hashes.add(hash);
        }

        let hashType = "";
        if (typeof action.hashType === "string") {
          hashType = action.hashType;
        }

        const binaryFileData: BinaryFileData = {
          name: fileName,
          path: fileName,
          hashType,
          hash,
        };

        res.push(binaryFileData);
      }
    }
  }
  return res;
}
