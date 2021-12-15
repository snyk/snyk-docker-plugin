import * as admzip from "adm-zip";
import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { JarFingerprintsFact } from "../../facts";
import { JarFingerprint } from "../types";
import { JarBuffer, JarDep, PomProperties } from "./types";
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
        dependencies: [],
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
  dependencies = [],
}: {
  jarBuffer: Buffer;
  jarPath: string;
  desiredLevelsOfUnpacking: number;
  unpackedLevels: number;
  jarBuffers: JarBuffer[];
  dependencies?: JarDep[];
}): JarBuffer[] {
  let isFatJar: boolean = false;

  if (unpackedLevels >= desiredLevelsOfUnpacking) {
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
      if (zipEntry.entryName.endsWith("pom.properties")) {
        dependencies = getDependenciesFromPomProperties(
          zipEntry,
          dependencies,
          jarPath,
        );
      }

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
          dependencies,
        });
      }
    }

    if (!isFatJar) {
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

interface ZipEntry {
  getData: () => Buffer;
}

function getDependenciesFromPomProperties(
  zipEntry: ZipEntry,
  dependencies: JarDep[],
  jarPath: string,
) {
  const result: JarDep[] = [...dependencies];

  const fileContentLines = zipEntry
    .getData()
    .toString()
    .split(/\n/)
    .filter((line) => /^[groupId|artifactId|version]=/.test(line)); // These are the only properties we are interested in
  const deps: PomProperties = fileContentLines.reduce((deps, line) => {
    const [key, value] = line.split("=");
    deps[key] = value.trim(); // Getting rid of EOL
    return deps;
  }, {});

  // Dependency shouldn't be a reference for the jar itself
  if (!jarPath.endsWith(`${deps.artifactId}-${deps.version}.jar`)) {
    result.push({
      name: deps.artifactId,
      parentName: deps.groupId,
      version: deps.version,
    });
  }

  return result;
}
