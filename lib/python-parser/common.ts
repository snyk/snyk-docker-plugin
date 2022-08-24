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
