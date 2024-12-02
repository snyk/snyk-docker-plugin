import * as admzip from "adm-zip";
import * as path from "path";
import { bufferToSha1 } from "../../buffer-utils";
import { ApplicationFilesFact, JarFingerprintsFact } from "../../facts";
import { Identity } from "../../types";
import { JarFingerprint } from "../types";
import {
  AggregatedJars,
  ApplicationFiles,
  JarBuffer,
  JarCoords,
  JarInfo,
} from "./types";
import { AppDepsScanResultWithoutTarget, FilePathToBuffer } from "./types";

/**
 * @param {{[fileName: string]: Buffer}} fileNameToBuffer fileName
 * @returns {AggregatedJars}
 */
function groupJarFingerprintsByPath(fileNameToBuffer: {
  [fileName: string]: Buffer;
}): AggregatedJars {
  const resultAggregatedByPath: AggregatedJars = {};
  Object.keys(fileNameToBuffer).forEach((filePath) => {
    const location = path.dirname(filePath);
    const jarFingerprint: JarInfo = {
      location: filePath,
      buffer: fileNameToBuffer[filePath],
      coords: null,
      dependencies: [],
      nestedJars: [],
    };
    resultAggregatedByPath[location] = resultAggregatedByPath[location] || [];
    resultAggregatedByPath[location].push(jarFingerprint);
  });

  return resultAggregatedByPath;
}

export async function jarFilesToScannedResults(
  filePathToContent: FilePathToBuffer,
  targetImage: string,
  desiredLevelsOfUnpacking: number,
  collectApplicationFiles: boolean,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const mappedResult = groupJarFingerprintsByPath(filePathToContent);
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const path in mappedResult) {
    if (!mappedResult.hasOwnProperty(path)) {
      continue;
    }

    const [fingerprints, classFiles] = await getFingerprints(
      desiredLevelsOfUnpacking,
      mappedResult[path],
      collectApplicationFiles,
    );

    const identity: Identity = {
      type: "maven",
      targetFile: path,
    };

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
      identity,
    });

    if (collectApplicationFiles && classFiles.length > 0) {
      const applicationFilesFact: ApplicationFilesFact = {
        type: "applicationFiles",
        data: classFiles,
      };
      scanResults.push({
        facts: [applicationFilesFact],
        identity,
      });
    }
  }

  return scanResults;
}

async function getFingerprints(
  desiredLevelsOfUnpacking: number,
  jarBuffers: JarBuffer[],
  collectApplicationFiles: boolean,
): Promise<[JarFingerprint[], ApplicationFiles[]]> {
  const [fingerprints, classFiles] = await unpackJars(
    jarBuffers,
    desiredLevelsOfUnpacking,
    collectApplicationFiles,
  );
  return [Array.from(new Set(fingerprints)), Array.from(new Set(classFiles))];
}

/**
 * Unpacks a JAR and attempts to add coords to the
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
 */
function unpackJar({
  jarBuffer,
  jarPath,
  desiredLevelsOfUnpacking,
  requiredLevelsOfUnpacking,
  unpackedLevels,
  collectApplicationFiles,
}: {
  jarBuffer: Buffer;
  jarPath: string;
  desiredLevelsOfUnpacking: number;
  requiredLevelsOfUnpacking: number;
  unpackedLevels: number;
  collectApplicationFiles: boolean;
}): JarInfo {
  const dependencies: JarCoords[] = [];
  const nestedJars: JarBuffer[] = [];
  const classFiles: ApplicationFiles = {
    language: "java",
    jarPath,
    fileHierarchy: [],
  };
  let coords: JarCoords | null = null;
  // Don't collect for nested jars
  const shouldCollectClassFiles =
    collectApplicationFiles && unpackedLevels <= 1;

  // TODO: consider switching to node-stream-zip that supports streaming
  let zip: admzip;
  let zipEntries: admzip.IZipEntry[];

  try {
    zip = new admzip(jarBuffer);
    zipEntries = zip.getEntries();
  } catch (err) {
    return {
      location: jarPath,
      buffer: jarBuffer,
      coords: null,
      dependencies,
      nestedJars,
    };
  }

  for (const zipEntry of zipEntries) {
    // pom.properties is file describing a package or package dependency
    // using this file allows resolution of shaded jars
    if (zipEntry.entryName.endsWith("pom.properties")) {
      const entryData = zipEntry.getData().toString();
      const entryCoords = getCoordsFromPomProperties(entryData);
      if (entryCoords) {
        if (
          // sometimes the path does not have the version
          jarPath.indexOf(
            `${entryCoords.artifactId}-${entryCoords.version}`,
          ) !== -1 ||
          jarPath.indexOf(`${entryCoords.artifactId}`) !== -1
        ) {
          coords = entryCoords;
        } else {
          dependencies.push(entryCoords);
        }
      }
    } else if (
      shouldCollectClassFiles &&
      zipEntry.entryName.endsWith(".class")
    ) {
      classFiles.fileHierarchy.push({ path: zipEntry.entryName });
    }

    // We only want to include JARs found at this level if the user asked for
    // unpacking using the --nested-jar-depth flag and we are in a level less
    // than the required level
    if (
      desiredLevelsOfUnpacking > 0 &&
      unpackedLevels < requiredLevelsOfUnpacking &&
      zipEntry.entryName.endsWith(".jar")
    ) {
      const entryData = zipEntry.getData();
      const entryName = zipEntry.entryName;

      nestedJars.push({
        buffer: entryData as Buffer,
        location: `${jarPath}/${entryName}`,
      });
    }
  }

  const result: JarInfo = {
    location: jarPath,
    buffer: jarBuffer,
    coords,
    dependencies,
    nestedJars,
  };

  if (shouldCollectClassFiles) {
    result.classFiles = classFiles;
  }

  return result;
}

/**
 * Manages the unpacking an array of JarBuffer objects and returns the resulting
 * fingerprints and classFiles (if requested). Recursion to required depth is handled here when the returned
 * info from each JAR that is unpacked has nestedJars.
 *
 * @param {JarBuffer[]} jarBuffers
 * @param {number} desiredLevelsOfUnpacking
 * @param {number} unpackedLevels
 * @returns [JarFingerprint[], string[]]
 */
async function unpackJars(
  jarBuffers: JarBuffer[],
  desiredLevelsOfUnpacking: number,
  collectApplicationFiles: boolean,
  unpackedLevels: number = 0,
): Promise<[JarFingerprint[], ApplicationFiles[]]> {
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
  const classFiles: ApplicationFiles[] = [];

  // jarBuffers is the array of JARS found in the image layers;
  // this represents the 1st "level" which we will unpack by
  // default to analyse. Any JARs found when analysing are nested
  // and we will keep going until we have no more nested JARs or
  // the desired level of unpacking is met
  for (const jarBuffer of jarBuffers) {
    const jarInfo = unpackJar({
      jarBuffer: jarBuffer.buffer,
      jarPath: jarBuffer.location,
      unpackedLevels: unpackedLevels + 1,
      desiredLevelsOfUnpacking,
      requiredLevelsOfUnpacking,
      collectApplicationFiles,
    });

    // we only care about JAR fingerprints. Other Java archive files are not
    // interesting enough on their own but are merely containers for JARs,
    // so no point in fingerprinting them
    if (jarBuffer.location.endsWith(".jar")) {
      // if any of the coords are null for this JAR we didn't manage to get
      // anything from the JAR's pom.properties manifest, so calculate the
      // sha so maven-deps can fallback to searching maven central
      fingerprints.push({
        location: jarInfo.location,
        digest: jarInfo.coords ? null : await bufferToSha1(jarInfo.buffer),
        dependencies: jarInfo.dependencies,
        ...jarInfo.coords,
      });
    }

    if (jarInfo.nestedJars.length > 0) {
      // this is an uber/fat JAR so we need to unpack the nested JARs to
      // analyze them for coords and further nested JARs (depth flag allowing)
      const [nestedJarFingerprints, newClassFiles] = await unpackJars(
        jarInfo.nestedJars,
        desiredLevelsOfUnpacking,
        collectApplicationFiles,
        unpackedLevels + 1,
      );
      fingerprints.push(...nestedJarFingerprints);
      if (collectApplicationFiles && newClassFiles?.length) {
        classFiles.push(...newClassFiles);
      }
    }

    if (collectApplicationFiles && jarInfo.classFiles) {
      classFiles.push(jarInfo.classFiles);
    }
  }

  return [fingerprints, classFiles];
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

  const coords: JarCoords = {};
  fileContentLines.forEach((line) => {
    const [key, value] = line.split("=");
    coords[key] = value.trim(); // Getting rid of EOL
  });
  return coords;
}
