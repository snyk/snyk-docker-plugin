import * as admzip from "adm-zip";
import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { JarFingerprintsFact } from "../../facts";
import { JarFingerprint } from "../types";
import { JarBuffer } from "./types";
import { AppDepsScanResultWithoutTarget, FilePathToBuffer } from "./types";
// tslint:disable:no-console

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
    // const jarDeps = getJarDeps(element);
    // console.log("🚀 ~ file: java.ts ~ line 88 ~ returnjarBuffers.map ~ jarDeps", jarDeps)

    return {
      ...element,
      digest: bufferToSha1(element.digest), // here we get {digest, location}? if so, need to add:
      // dependencies: []
      // {groupId: string; artifactId: string; version: string;}
      //
    };
  });
}

// function getJarDeps(jarBuffer) {
//   return;
// }

function unpackJarsTraverse({
  jarBuffer,
  jarPath,
  desiredLevelsOfUnpacking,
  unpackedLevels,
  jarBuffers,
  dependencies = [],
}: {
  jarBuffer: Buffer;
  jarPath: string;
  desiredLevelsOfUnpacking: number;
  unpackedLevels: number;
  jarBuffers: JarBuffer[];
  dependencies?: any;
}): JarBuffer[] {
  console.log("jarPath: ", jarPath);
  let isFatJar: boolean = false;

  // console.log("🚀 ~ file: java.ts ~ line 127 ~ desiredLevelsOfUnpacking", desiredLevelsOfUnpacking)
  if (unpackedLevels >= desiredLevelsOfUnpacking) {
    // here?
    jarBuffers.push({
      location: jarPath,
      digest: jarBuffer,
      dependencies,
    });
  } else {
    const zip = new admzip(jarBuffer);
    const zipEntries = zip.getEntries();

    // technically the level should be increased only if a JAR is found, but increasing here to make
    // sure it states the level, and not counting all the jars found, regardless of level.
    unpackedLevels = unpackedLevels + 1;

    for (const zipEntry of zipEntries) {
      // console.log(zipEntry.entryName);
      if (zipEntry.entryName.endsWith("pom.properties")) {
        console.log(zipEntry.entryName);
        dependencies.push(zipEntry.entryName as never);
      }

      if (zipEntry.entryName.endsWith(".jar")) {
        console.log(
          "🚀 ~ file: java.ts ~ line 145 ~ zipEntry.entryName",
          zipEntry.entryName,
        );
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
          dependencies,
        });
      }
    }

    if (!isFatJar) {
      // here??

      jarBuffers.push({
        location: jarPath,
        digest: jarBuffer,
        dependencies,
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
