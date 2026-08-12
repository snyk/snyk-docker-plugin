export type SbomFormat = "cyclonedx1.5+json";

const SUPPORTED_SBOM_FORMAT = "cyclonedx1.5+json";

/**
 * Parses and validates the `sbom-format` plugin option.
 *
 * @returns the normalized format when SBOM generation is requested, otherwise
 * `undefined` when the option is absent.
 * @throws when the value is present but not a supported format.
 */
export function parseSbomFormat(
  value?: boolean | string | null,
): SbomFormat | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  const normalized = String(value).trim().toLowerCase();
  if (normalized === SUPPORTED_SBOM_FORMAT) {
    return SUPPORTED_SBOM_FORMAT;
  }

  throw new Error(
    `Unsupported SBOM format: ${value}. Supported values: ${SUPPORTED_SBOM_FORMAT}`,
  );
}
