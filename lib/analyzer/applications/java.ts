import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { JarFingerprintsFact } from "../../facts";
import { JarBuffer } from "./types";
import { AppDepsScanResultWithoutTarget, FilePathToBuffer } from "./types";

function groupJarFingerprintsByPath(input: {
  [fileName: string]: Buffer;
}): {
  [path: string]: JarBuffer[];
} {
  const jarFingerprints: JarBuffer[] = Object.entries(input).map(
    ([filePath, digest]) => {
      return {
        location: filePath,
        digest,
      };
    },
  );

  const resultAggregatedByPath = jarFingerprints.reduce(
    (jarsAggregatedByPath, jarFingerprint) => {
      const location = path.dirname(jarFingerprint.location);
      jarsAggregatedByPath[location] = jarsAggregatedByPath[location] || [];
      jarsAggregatedByPath[location].push(jarFingerprint);
      return jarsAggregatedByPath;
    },
    {},
  );

  return resultAggregatedByPath;
}

export async function jarFilesToScannedProjects(
  filePathToContent: FilePathToBuffer,
  targetImage: string,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const mappedResult = groupJarFingerprintsByPath(filePathToContent);
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const path in mappedResult) {
    if (!mappedResult.hasOwnProperty(path)) {
      continue;
    }
    const jarFingerprintsFact: JarFingerprintsFact = {
      type: "jarFingerprints",
      data: {
        fingerprints: mappedResult[path].map((element) => {
          return {
            ...element,
            digest: bufferToSha1(element.digest),
          };
        }),
        origin: targetImage,
        path,
      },
    };
    scanResults.push({
      facts: [jarFingerprintsFact],
      identity: {
        type: "maven",
        targetFile: path,
      },
    });
  }

  return scanResults;
}
