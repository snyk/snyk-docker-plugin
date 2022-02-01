import * as admzip from "adm-zip";
import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { JarFingerprintsFact } from "../../facts";
import { JarFingerprint } from "../types";
import { JarBuffer, JarCoords } from "./types";
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
        coords: null,
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
  return unpackJars(jarBuffers, desiredLevelsOfUnpacking);
}

/**
 * Recursively unpacks JARs and attempts to add coords to the
 * package and it's dependencies.
 *
 * JARs will always be unpacked one level more than requested
 * by the end-user in order to look for manifest files but will
 * ignore any JARs found for a level deeper than the user request.
 *
 * NOTE: desiredLevelsOfUnpacking and requiredLevelsOfUnpacking
 * are used to be explicit in nature and distinguish between the
 * level of JAR detection requested by the user and the level of
 * unpacking used in the implementation.
 * @param { object } props
 * @param { Buffer } props.jarBuffer
 * @param { string } props.jarPath
 * @param { number } props.desiredLevelsOfUnpacking
 * @param { number } props.requiredLevelsOfUnpacking
 * @param { number } props.unpackedLevels
 * @param { JarBuffer[] } props.jarBuffers
 * @param { JarCoords | null } props.coords
 * @param { JarCoords[] } props.dependencies
 */
function unpackJarsTraverse({
  jarBuffer,
  jarPath,
  desiredLevelsOfUnpacking,
  requiredLevelsOfUnpacking,
  unpackedLevels,
  jarBuffers,
  coords = null,
  dependencies = [],
}: {
  jarBuffer: Buffer;
  jarPath: string;
  desiredLevelsOfUnpacking: number;
  requiredLevelsOfUnpacking: number;
  unpackedLevels: number;
  jarBuffers: JarBuffer[];
  coords: JarCoords | null;
  dependencies?: JarCoords[];
}): JarBuffer[] {
  let isFatJar: boolean = false;
  let zip: admzip;
  let zipEntries: admzip.IZipEntry[];

  try {
    zip = new admzip(jarBuffer);
    zipEntries = zip.getEntries();
  } catch (err) {
    jarBuffers.push({
      location: jarPath,
      digest: jarBuffer,
      dependencies,
      coords: null,
    });

    return jarBuffers;
  }

  // technically the level should be increased only if a JAR is found, but increasing here to make
  // sure it states the level, and not counting all the jars found, regardless of level.
  unpackedLevels = unpackedLevels + 1;

  for (const zipEntry of zipEntries) {
    // pom.properties is file describing a package or package dependency
    // using this file allows resolution of shaded jars
    if (zipEntry.entryName.endsWith("pom.properties")) {
      const entryData = zipEntry.getData().toString();
      const entryCoords = getCoordsFromPomProperties(entryData);
      if (entryCoords) {
        if (
          // sometimes the path does not have the version
          jarPath.endsWith(
            `${entryCoords.artifactId}-${entryCoords.version}.jar`,
          ) ||
          jarPath.endsWith(`${entryCoords.artifactId}.jar`)
        ) {
          coords = entryCoords;
        } else {
          dependencies.push(entryCoords);
        }
      }
    }

    // We only want to include JARs found at this level if the user asked for
    // unpacking using the --nested-jar-depth flag and we are in a level less
    // than the required level
    if (
      desiredLevelsOfUnpacking > 0 &&
      unpackedLevels < requiredLevelsOfUnpacking &&
      zipEntry.entryName.endsWith(".jar")
    ) {
      isFatJar = true;
      const entryData = zipEntry.getData();
      const entryName = zipEntry.entryName;
      jarPath = `${jarPath}/${entryName}`;

      unpackJarsTraverse({
        jarBuffer: entryData,
        jarPath,
        desiredLevelsOfUnpacking,
        requiredLevelsOfUnpacking,
        unpackedLevels,
        jarBuffers,
        coords,
        dependencies,
      });
    }
  }

  if (!isFatJar) {
    jarBuffers.push({
      location: jarPath,
      digest: jarBuffer,
      coords,
      dependencies,
    });
  }

  return jarBuffers;
}

function unpackJars(
  jarBuffers: JarBuffer[],
  desiredLevelsOfUnpacking: number,
): JarFingerprint[] {
  // We have to unpack jars to get the pom.properties manifest which
  // we use to support shaded jars and get the package coords (if exists)
  // to reduce the dependency on maven search and support private jars.
  // This means that we must unpack 1 more level than customer requests
  // via --nested-jar-depth option in CLI and the default value for
  // K8S and DRA integrations
  //
  // desiredLevelsOfUnpacking  = user specified (--nested-jar-depth) or default
  // requiredLevelsOfUnpacking = implementation control variable
  const requiredLevelsOfUnpacking = desiredLevelsOfUnpacking + 1;
  const fingerprints: JarFingerprint[] = [];

  for (const jarBuffer of jarBuffers) {
    const unpackedLevels: number = 0;
    const jars: JarBuffer[] = unpackJarsTraverse({
      jarBuffer: jarBuffer.digest,
      jarPath: jarBuffer.location,
      desiredLevelsOfUnpacking,
      requiredLevelsOfUnpacking,
      unpackedLevels,
      coords: null,
      jarBuffers: [],
    });

    // if any of the coords are null for this JAR we didn't manage to get
    // anything from the JAR's pom.properties manifest, so calculate the
    // sha so maven-deps can fallback to searching maven central
    jars.forEach((jar) => {
      fingerprints.push({
        location: jar.location,
        digest: jar.coords ? null : bufferToSha1(jar.digest),
        dependencies: jar.dependencies,
        ...jar.coords,
      });
    });
  }

  return fingerprints;
}

/**
 * Gets coords from the contents of a pom.properties file
 * @param {string} fileContent
 * @param {string} jarPath
 */
export function getCoordsFromPomProperties(
  fileContent: string,
): JarCoords | null {
  const coords = parsePomProperties(fileContent);

  // we need all of these props to allow us to inject the package
  // into the depGraph
  if (!coords.artifactId || !coords.groupId || !coords.version) {
    return null;
  }

  return coords;
}

/**
 * Parses the file content of a pom.properties file to extract
 * the coords for a package.
 * @param {string} fileContent
 */
export function parsePomProperties(fileContent: string): JarCoords {
  const fileContentLines = fileContent
    .split(/\n/)
    .filter((line) => /^(groupId|artifactId|version)=/.test(line)); // These are the only properties we are interested in
  const coords: JarCoords = fileContentLines.reduce((coords, line) => {
    const [key, value] = line.split("=");
    coords[key] = value.trim(); // Getting rid of EOL
    return coords;
  }, {});

  return coords;
}
