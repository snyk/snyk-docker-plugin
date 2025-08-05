import * as Debug from "debug";
import { ParsedSBOM, SBOMPackage } from "../sbom-parsers";
import { AnalyzedPackageWithVersion } from "../types";

const debug = Debug("snyk:sbom:converter");

/**
 * Converts a single SBOM package to AnalyzedPackageWithVersion format
 */
export function convertSBOMPackageToAnalyzed(
  sbomPackage: SBOMPackage,
  filePath: string,
  sbomName: string,
): AnalyzedPackageWithVersion {
  // Build dependencies object
  const deps: { [name: string]: any } = {};
  if (sbomPackage.dependencies) {
    for (const dep of sbomPackage.dependencies) {
      deps[dep] = {};
    }
  }

  return {
    Name: sbomPackage.name,
    Version: sbomPackage.version,
    Source: "sbom", // Mark this as SBOM-sourced for traceability
    SourceVersion: sbomPackage.version,
    Provides: [], // SBOM packages typically don't have provides information
    Deps: deps,
    Purl: sbomPackage.purl,
    AutoInstalled: false, // SBOM packages are considered explicitly declared
  };
}

/**
 * Converts all packages from a parsed SBOM to AnalyzedPackageWithVersion format
 */
export function convertSBOMToAnalyzedPackages(
  parsedSBOM: ParsedSBOM,
): AnalyzedPackageWithVersion[] {
  const { document, filePath } = parsedSBOM;

  debug(
    `Converting ${document.packages.length} packages from SBOM: ${filePath}`,
  );

  const analyzedPackages: AnalyzedPackageWithVersion[] = [];

  for (const sbomPackage of document.packages) {
    try {
      const analyzed = convertSBOMPackageToAnalyzed(
        sbomPackage,
        filePath,
        document.name,
      );
      analyzedPackages.push(analyzed);
    } catch (error) {
      debug(
        `Error converting SBOM package ${sbomPackage.name}: ${error.message}`,
      );
    }
  }

  debug(`Successfully converted ${analyzedPackages.length} packages from SBOM`);
  return analyzedPackages;
}

/**
 * Converts multiple parsed SBOMs to AnalyzedPackageWithVersion format
 */
export function convertMultipleSBOMsToAnalyzedPackages(
  parsedSBOMs: ParsedSBOM[],
): AnalyzedPackageWithVersion[] {
  const allPackages: AnalyzedPackageWithVersion[] = [];

  for (const parsedSBOM of parsedSBOMs) {
    const packages = convertSBOMToAnalyzedPackages(parsedSBOM);
    allPackages.push(...packages);
  }

  // Deduplicate packages by name and version
  const uniquePackages = deduplicatePackages(allPackages);

  debug(
    `Converted ${allPackages.length} total packages, ${uniquePackages.length} unique packages from ${parsedSBOMs.length} SBOMs`,
  );
  return uniquePackages;
}

/**
 * Deduplicates packages by name and version, keeping the first occurrence
 */
function deduplicatePackages(
  packages: AnalyzedPackageWithVersion[],
): AnalyzedPackageWithVersion[] {
  const seen = new Set<string>();
  const uniquePackages: AnalyzedPackageWithVersion[] = [];

  for (const pkg of packages) {
    const key = `${pkg.Name}@${pkg.Version}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniquePackages.push(pkg);
    } else {
      debug(`Duplicate package found and skipped: ${key}`);
    }
  }

  return uniquePackages;
}

/**
 * Validates that an SBOM package has the minimum required fields
 */
export function validateSBOMPackage(sbomPackage: SBOMPackage): boolean {
  if (!sbomPackage.name || !sbomPackage.version) {
    debug(`Invalid SBOM package: missing name or version`, sbomPackage);
    return false;
  }

  if (sbomPackage.version === "unknown" || sbomPackage.version === "") {
    debug(`SBOM package has unknown version: ${sbomPackage.name}`);
    return false;
  }

  return true;
}

/**
 * Filters out invalid SBOM packages before conversion
 */
export function filterValidSBOMPackages(
  packages: SBOMPackage[],
): SBOMPackage[] {
  return packages.filter(validateSBOMPackage);
}
