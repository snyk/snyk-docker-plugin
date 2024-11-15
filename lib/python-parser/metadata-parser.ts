import * as semver from "semver";
import { parseExtraNames, specifierValidRange } from "./common";
import { findProvidesExtras } from "./provides-extra";
import type { PythonPackage, PythonRequirement } from "./types";

const PACKAGE_NAME = "Name: ";
const PACKAGE_VERSION = "Version: ";
const PACKAGE_DEPS = "Requires-Dist: ";
const DEP_PARSE_REGEX =
  /^(?<name>[\w.-]+)((\[(?<extras>.*)\])?)(\s?\(?(?<specifier><|<=|!=|==|>=|>|~=|===)(?<version>[\w.]+)\)?)?/;

export function getPackageInfo(fileContent: string): PythonPackage {
  const lines = fileContent.split("\n");
  const providesExtras = findProvidesExtras(lines);
  let name = "";
  let version = "";
  const dependencies: PythonRequirement[] = [];
  for (let line of lines) {
    line = line.trim();
    if (line.length === 0) {
      continue;
    }
    if (line.startsWith(PACKAGE_NAME)) {
      name = line.substring(PACKAGE_NAME.length);
    } else if (line.startsWith(PACKAGE_VERSION)) {
      version = line.substring(PACKAGE_VERSION.length);
    } else if (line.startsWith(PACKAGE_DEPS)) {
      const pythonPackage = parseDependency(
        line.substring(PACKAGE_DEPS.length),
        providesExtras,
      );
      if (pythonPackage) {
        dependencies.push(pythonPackage);
      }
    }
  }
  const validVersion = getParseableVersion(version);
  return {
    name: name.toLowerCase(),
    version: validVersion,
    dependencies,
  } as PythonPackage;
}

// parse a line containing a dependency package name & extras and (optional) specifier + version
export function parseDependency(
  packageDependency: string,
  providesExtras: string[],
): PythonRequirement | null {
  packageDependency = packageDependency.trim();

  const parsedDep = DEP_PARSE_REGEX.exec(packageDependency);
  if (!parsedDep?.groups) {
    return null;
  }
  const { name, extras, version, specifier } = parsedDep.groups;

  return {
    name: name.toLowerCase(),
    version,
    specifier: specifierValidRange(specifier, version),
    extras: parseExtraNames(extras),
    extraEnvMarkers: parseExtraEnvMarkers(providesExtras, packageDependency),
  } as PythonRequirement;
}

// parse extra environment markers located after the quoted marker
// see https://peps.python.org/pep-0508
function parseExtraEnvMarkers(
  providesExtras: string[],
  requiresDist?: string,
): string[] {
  const extraNames = new Set<string>();

  // search string after quoted_marker ;
  const quotedMarker = requiresDist?.split(";");
  if (quotedMarker && quotedMarker.length > 1) {
    for (const extra of providesExtras) {
      // search for extra env markers for given provides extras
      const re = new RegExp(`.*extra.*("|')(?<extra>${extra})("|').*`);
      if (re.exec(quotedMarker[1])) {
        extraNames.add(extra);
      }
    }
  }

  return Array.from(extraNames);
}

function getParseableVersion(versionString: string): string {
  const validVersion = semver.coerce(versionString);
  if (!validVersion) {
    throw new PythonInvalidVersionError(
      `version ${versionString} is not compatible with semver and cannot be compared`,
    );
  }
  if (
    versionString.indexOf(validVersion.version) === 0 &&
    /^\d+(\.\d+)+$/.test(versionString)
  ) {
    return versionString;
  }
  return validVersion.version;
}

export class PythonInvalidVersionError extends Error {}
