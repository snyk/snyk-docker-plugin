import * as admzip from "adm-zip";
import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { JarFingerprintsFact } from "../../facts";
import { JarFingerprint } from "../types";
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

    const fingerprints = getFingerprints(
      desiredLevelsOfUnpacking,
      mappedResult[path],
    );

    const jarFingerprintsFact: JarFingerprintsFact = {
      type: "jarFingerprints",
      data: {
        fingerprints,
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

function getFingerprints(
  desiredLevelsOfUnpacking: number,
  jarBuffers: JarBuffer[],
): JarFingerprint[] {
  if (desiredLevelsOfUnpacking === 0) {
    return getJarShas(jarBuffers);
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
  jarBuffers,
}: {
  jarBuffer: Buffer;
  jarPath: string;
  desiredLevelsOfUnpacking: number;
  unpackedLevels: number;
  jarBuffers: JarBuffer[];
}): JarBuffer[] {
  let isFatJar: boolean = false;

  if (unpackedLevels >= desiredLevelsOfUnpacking) {
    jarBuffers.push({
      location: jarPath,
      digest: jarBuffer,
    });
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
          jarBuffers,
        });
      }
    }

    if (!isFatJar) {
      jarBuffers.push({
        location: jarPath,
        digest: jarBuffer,
      });
    }
  }

  return jarBuffers;
}

function unpackFatJars(
  jarBuffers: JarBuffer[],
  desiredLevelsOfUnpacking: number,
): JarFingerprint[] {
  const fingerprints: JarFingerprint[] = [];

  for (const jarBuffer of jarBuffers) {
    const unpackedLevels: number = 0;
    const jars: JarBuffer[] = unpackJarsTraverse({
      jarBuffer: jarBuffer.digest,
      jarPath: jarBuffer.location,
      desiredLevelsOfUnpacking,
      unpackedLevels,
      jarBuffers: [],
    });

    fingerprints.push(...getJarShas(jars));
  }

  return fingerprints;
}