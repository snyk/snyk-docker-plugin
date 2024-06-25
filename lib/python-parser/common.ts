export function specifierValidRange(
  specifier: string,
  version: string,
): string {
  specifier =
    specifier === "==" || specifier === "===" || specifier === "~="
      ? specifier.charAt(0)
      : specifier;
  if (specifier !== "~") {
    return specifier;
  }
  // the tilde specifier in a requirements file means different things, depending on the
  // way the version is provided. In order for the semver library to compare as expected,
  // we need to change the specifier to something it understands.
  // see https://peps.python.org/pep-0440/#compatible-release
  const versionPartsLength = version.split(".").length;
  return versionPartsLength === 2 ? "^" : "~";
}

// This regex is used to extract the "semver" part from the version string.
// See the tests for a better understanding (Also the reason why this is exported)
export const VERSION_EXTRACTION_REGEX = /(?<VERSION>(\d+\.)*\d+).*/;

function compareArrays(v1: number[], v2: number[]) {
  const max = v1.length > v2.length ? v1.length : v2.length;
  for (let i = 0; i < max; i++) {
    if ((v1[i] || 0) < (v2[i] || 0)) {
      return 1;
    }
    if ((v1[i] || 0) > (v2[i] || 0)) {
      return -1;
    }
  }
  return 0;
}

/**
 * This function was taken from a different semver library and slightly modified.
 * If passed to Array.prototype.sort, versions will be sorted in descending order.
 */
export function compareVersions(version1: string, version2: string) {
  const v1Match = VERSION_EXTRACTION_REGEX.exec(version1);
  const v2Match = VERSION_EXTRACTION_REGEX.exec(version2);

  if (v1Match === null || v2Match === null) {
    return 0;
  }

  const v1 = v1Match
    .groups!.VERSION.split(".")
    .map((part) => Number.parseInt(part, 10));
  const v2 = v2Match
    .groups!.VERSION.split(".")
    .map((part) => Number.parseInt(part, 10));

  return compareArrays(v1, v2);
}
