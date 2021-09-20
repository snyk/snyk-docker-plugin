import * as admzip from "adm-zip";
import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { JarFingerprintsFact } from "../../facts";
import {
  JarAnalysisResult,
  JarFingerprint,
  UnpackedJarsResult,
} from "../types";
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
  desiredLevelsOfUnpacking: number,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const mappedResult = groupJarFingerprintsByPath(filePathToContent);
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const path in mappedResult) {
    if (!mappedResult.hasOwnProperty(path)) {
      continue;
    }

    const { fingerprints, unpackedLevels } = getFingerprints(
      desiredLevelsOfUnpacking,
      mappedResult[path],
    );

    const jarFingerprintsFact: JarFingerprintsFact = {
      type: "jarFingerprints",
      data: {
        fingerprints,
        origin: targetImage,
        path,
        shadedJarsUnpackedLevel: unpackedLevels,
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

function getFingerprints(
  desiredLevelsOfUnpacking: number,
  jarBuffers: JarBuffer[],
): JarAnalysisResult {
  if (desiredLevelsOfUnpacking === 0) {
    return { fingerprints: getJarShas(jarBuffers), unpackedLevels: 0 };
  }

  return unpackFatJars(jarBuffers, desiredLevelsOfUnpacking);
}

function getJarShas(jarBuffers: JarBuffer[]): JarFingerprint[] {
  return jarBuffers.map((element) => {
    return {
      ...element,
      digest: bufferToSha1(element.digest),
    };
  });
}

function unpackJarsTraverse({
  jarBuffer,
  jarPath,
  desiredLevelsOfUnpacking,
  unpackedLevels,
  allUnpackedLevels,
  jarBuffers,
}: {
  jarBuffer: Buffer;
  jarPath: string;
  desiredLevelsOfUnpacking: number;
  unpackedLevels: number;
  allUnpackedLevels: number[];
  jarBuffers: JarBuffer[];
}): UnpackedJarsResult {
  let isFatJar: boolean = false;

  if (unpackedLevels >= desiredLevelsOfUnpacking) {
    jarBuffers.push({
      location: jarPath,
      digest: jarBuffer,
    });
    allUnpackedLevels.push(unpackedLevels);
  } else {
    const zip = new admzip(jarBuffer);
    const zipEntries = zip.getEntries();

    // technically the level should be increased only if a JAR is found, but increasing here to make
    // sure it states the level, and not counting all the jars found, regardless of level.
    unpackedLevels = unpackedLevels + 1;

    for (const zipEntry of zipEntries) {
      if (zipEntry.entryName.endsWith(".jar")) {
        isFatJar = true;
        const entryData = zipEntry.getData();
        const entryName = zipEntry.entryName;
        jarPath = `${jarPath}/${entryName}`;

        unpackJarsTraverse({
          jarBuffer: entryData,
          jarPath,
          desiredLevelsOfUnpacking,
          unpackedLevels,
          allUnpackedLevels,
          jarBuffers,
        });
      }
    }

    if (!isFatJar) {
      jarBuffers.push({
        location: jarPath,
        digest: jarBuffer,
      });
      allUnpackedLevels.push(unpackedLevels);
    }
  }

  return { jarBuffers, allUnpackedLevels };
}

function unpackFatJars(
  jarBuffers: JarBuffer[],
  desiredLevelsOfUnpacking: number,
): JarAnalysisResult {
  const fingerprints: JarFingerprint[] = [];
  const allUnpackedLevels: number[] = [];

  for (const jarBuffer of jarBuffers) {
    const unpackedJarsResult: UnpackedJarsResult = unpackJarsTraverse({
      jarBuffer: jarBuffer.digest,
      jarPath: jarBuffer.location,
      desiredLevelsOfUnpacking,
      unpackedLevels: 0,
      allUnpackedLevels,
      jarBuffers: [],
    });

    fingerprints.push(...getJarShas(unpackedJarsResult.jarBuffers));
    allUnpackedLevels.push(...unpackedJarsResult.allUnpackedLevels);
  }

  return { fingerprints, unpackedLevels: Math.max(...allUnpackedLevels) };
}
