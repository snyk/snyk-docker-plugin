import * as admzip from "adm-zip";
import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { JarFingerprintsFact } from "../../facts";
import { JarFingerprint } from "../types";
import { JarBuffer, JarDep, PomProperties } from "./types";
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
  let zip;
  let zipEntries;

  if (unpackedLevels >= desiredLevelsOfUnpacking) {
    jarBuffers.push({
      location: jarPath,
      digest: jarBuffer,
      dependencies,
    });
  } else {
    try {
      zip = new admzip(jarBuffer);
      zipEntries = zip.getEntries();
    } catch (err) {
      jarBuffers.push({
        location: jarPath,
        digest: jarBuffer,
        dependencies,
      });

      return jarBuffers;
    }

    // technically the level should be increased only if a JAR is found, but increasing here to make
    // sure it states the level, and not counting all the jars found, regardless of level.
    unpackedLevels = unpackedLevels + 1;

    for (const zipEntry of zipEntries) {
      // pom.properties is file describing a dependency within a JAR
      // using this file allows resolution of shaded jars
      if (zipEntry.entryName.endsWith("pom.properties")) {
        const entryData = zipEntry.getData().toString();
        const dep = getDependencyFromPomProperties(entryData, jarPath);
        if (dep) {
          dependencies.push(dep);
        }
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

/**
 * Gets a formatted dependency object from the contents of
 * a pom.properties file that describes a JAR dependency
 * @param {string} fileContent
 * @param {string} jarPath
 */
export function getDependencyFromPomProperties(
  fileContent: string,
  jarPath: string,
): JarDep | null {
  const dep = parsePomProperties(fileContent);

  // we need all of these props to allow us to inject the dependency
  // into the depGraph
  if (!dep.name || !dep.parentName || !dep.version) {
    return null;
  }
  // Dependency shouldn't be a reference for the JAR itself
  if (dep && !jarPath.endsWith(`${dep.name}-${dep.version}.jar`)) {
    return dep;
  }

  return null;
}

/**
 * Parses the file content of a pom.properties file to extract
 * the "fields" for a JAR dependency.
 * @param {string} fileContent
 */
export function parsePomProperties(fileContent: string): JarDep {
  const fileContentLines = fileContent
    .split(/\n/)
    .filter((line) => /^(groupId|artifactId|version)=/.test(line)); // These are the only properties we are interested in
  const dep: PomProperties = fileContentLines.reduce((dep, line) => {
    const [key, value] = line.split("=");
    dep[key] = value.trim(); // Getting rid of EOL
    return dep;
  }, {});

  return {
    name: dep.artifactId,
    parentName: dep.groupId,
    version: dep.version,
  };
}
