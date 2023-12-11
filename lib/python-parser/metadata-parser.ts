import * as semver from "semver";
import { specifierValidRange } from "./common";
import { PythonPackage, PythonRequirement } from "./types";

const PACKAGE_NAME = "Name: ";
const PACKAGE_VERSION = "Version: ";
const PACKAGE_DEPS = "Requires-Dist: ";
const DEP_PARSE_REGEX =
  /^(?<name>[\w.-]+)(\s?\(?(?<specifier><|<=|!=|==|>=|>|~=|===)(?<version>[\w.]+)\)?)?/;
export function getPackageInfo(fileContent: string): PythonPackage {
  const lines = fileContent.split("\n");
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

// parse a line containing a dependency package name and (optional) specifier + version
function parseDependency(packageDependency: string): PythonRequirement | null {
  packageDependency = packageDependency.trim();
  const parsedDep = DEP_PARSE_REGEX.exec(packageDependency);
  if (!parsedDep?.groups) {
    return null;
  }
  const { name, version, specifier } = parsedDep.groups;
  const correctedSpecifier = specifierValidRange(specifier, version);
  return {
    name: name.toLowerCase(),
    version,
    specifier: correctedSpecifier,
  } as PythonRequirement;
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
