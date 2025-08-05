import * as Debug from "debug";
import { PluginOptions } from "../../types";
import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../types";

const debug = Debug("snyk:sbom:merger");

export type SBOMMergeStrategy =
  | "ignore"
  | "supplement"
  | "override"
  | "validate";

export interface SBOMMergeOptions {
  strategy: SBOMMergeStrategy;
  precedence: "filesystem" | "sbom";
  strictValidation: boolean;
}

export interface MergeResult {
  mergedResults: ImagePackagesAnalysis[];
  sbomPackagesAdded: number;
  conflictsResolved: number;
  validationIssues: string[];
}

/**
 * Main function to merge SBOM packages with existing analysis results
 */
export function mergeSBOMWithResults(
  existingResults: ImagePackagesAnalysis[],
  sbomPackages: AnalyzedPackageWithVersion[],
  options: Partial<PluginOptions>,
): MergeResult {
  const mergeOptions: SBOMMergeOptions = {
    strategy: (options["sbom-merge-strategy"] as SBOMMergeStrategy) || "ignore",
    precedence:
      (options["sbom-precedence"] as "filesystem" | "sbom") || "filesystem",
    strictValidation: options["sbom-validation-strict"] === true,
  };

  debug(
    `Merging SBOM packages with strategy: ${mergeOptions.strategy}, precedence: ${mergeOptions.precedence}`,
  );

  switch (mergeOptions.strategy) {
    case "ignore":
      return ignoreWithSBOM(existingResults, sbomPackages, mergeOptions);
    case "supplement":
      return supplementWithSBOM(existingResults, sbomPackages, mergeOptions);
    case "override":
      return overrideWithSBOM(existingResults, sbomPackages, mergeOptions);
    case "validate":
      return validateWithSBOM(existingResults, sbomPackages, mergeOptions);
    default:
      debug(
        `Unknown merge strategy: ${mergeOptions.strategy}, falling back to ignore`,
      );
      return ignoreWithSBOM(existingResults, sbomPackages, mergeOptions);
  }
}

/**
 * Ignore strategy: Return existing results without any SBOM modifications
 */
function ignoreWithSBOM(
  existingResults: ImagePackagesAnalysis[],
  sbomPackages: AnalyzedPackageWithVersion[],
  options: SBOMMergeOptions,
): MergeResult {
  debug(
    `Ignoring ${sbomPackages.length} SBOM packages - no modifications to existing results`,
  );

  return {
    mergedResults: [...existingResults],
    sbomPackagesAdded: 0,
    conflictsResolved: 0,
    validationIssues: [],
  };
}

/**
 * Supplement strategy: Add SBOM packages that are not already detected
 */
function supplementWithSBOM(
  existingResults: ImagePackagesAnalysis[],
  sbomPackages: AnalyzedPackageWithVersion[],
  options: SBOMMergeOptions,
): MergeResult {
  const mergedResults = [...existingResults];
  let sbomPackagesAdded = 0;
  const validationIssues: string[] = [];

  // Create a map of existing packages for quick lookup
  const existingPackageMap = new Map<string, AnalyzedPackageWithVersion>();
  for (const result of existingResults) {
    for (const pkg of result.Analysis) {
      const key = `${pkg.Name}@${pkg.Version}`;
      existingPackageMap.set(key, pkg);
    }
  }

  // Find SBOM packages that don't exist in filesystem analysis
  const newPackages: AnalyzedPackageWithVersion[] = [];
  for (const sbomPkg of sbomPackages) {
    const key = `${sbomPkg.Name}@${sbomPkg.Version}`;
    if (!existingPackageMap.has(key)) {
      newPackages.push(sbomPkg);
      sbomPackagesAdded++;
    } else {
      debug(`Package ${key} already exists, skipping supplement`);
    }
  }

  // Add new packages to results
  if (newPackages.length > 0) {
    // Find or create an SBOM analysis result
    let sbomAnalysis = mergedResults.find(
      (result) => result.AnalyzeType === AnalysisType.Linux,
    );

    if (!sbomAnalysis) {
      sbomAnalysis = {
        Image: "sbom-packages",
        AnalyzeType: AnalysisType.Linux,
        Analysis: [],
      };
      mergedResults.push(sbomAnalysis);
    }

    sbomAnalysis.Analysis.push(...newPackages);
    debug(`Added ${newPackages.length} new packages from SBOM`);
  }

  return {
    mergedResults,
    sbomPackagesAdded,
    conflictsResolved: 0,
    validationIssues,
  };
}

/**
 * Override strategy: Replace existing packages with SBOM versions when conflicts exist
 */
function overrideWithSBOM(
  existingResults: ImagePackagesAnalysis[],
  sbomPackages: AnalyzedPackageWithVersion[],
  options: SBOMMergeOptions,
): MergeResult {
  const mergedResults = [...existingResults];
  let sbomPackagesAdded = 0;
  let conflictsResolved = 0;
  const validationIssues: string[] = [];

  // Create SBOM package map for quick lookup
  const sbomPackageMap = new Map<string, AnalyzedPackageWithVersion>();
  for (const sbomPkg of sbomPackages) {
    const nameKey = sbomPkg.Name;
    sbomPackageMap.set(nameKey, sbomPkg);
  }

  // Process each existing result
  for (const result of mergedResults) {
    const updatedAnalysis: AnalyzedPackageWithVersion[] = [];

    for (const existingPkg of result.Analysis) {
      const sbomPkg = sbomPackageMap.get(existingPkg.Name);

      if (sbomPkg) {
        // Conflict found - decide based on precedence
        if (options.precedence === "sbom") {
          updatedAnalysis.push(sbomPkg);
          conflictsResolved++;
          debug(
            `Replaced ${existingPkg.Name}@${existingPkg.Version} with SBOM version @${sbomPkg.Version}`,
          );
        } else {
          updatedAnalysis.push(existingPkg);
          debug(
            `Kept filesystem version of ${existingPkg.Name}@${existingPkg.Version} over SBOM @${sbomPkg.Version}`,
          );
        }
        sbomPackageMap.delete(existingPkg.Name); // Remove to track what's left
      } else {
        updatedAnalysis.push(existingPkg);
      }
    }

    result.Analysis = updatedAnalysis;
  }

  // Add remaining SBOM packages that had no conflicts
  const remainingSBOMPackages = Array.from(sbomPackageMap.values());
  if (remainingSBOMPackages.length > 0) {
    let sbomAnalysis = mergedResults.find(
      (result) => result.AnalyzeType === AnalysisType.Linux,
    );

    if (!sbomAnalysis) {
      sbomAnalysis = {
        Image: "sbom-packages",
        AnalyzeType: AnalysisType.Linux,
        Analysis: [],
      };
      mergedResults.push(sbomAnalysis);
    }

    sbomAnalysis.Analysis.push(...remainingSBOMPackages);
    sbomPackagesAdded = remainingSBOMPackages.length;
  }

  return {
    mergedResults,
    sbomPackagesAdded,
    conflictsResolved,
    validationIssues,
  };
}

/**
 * Validate strategy: Compare SBOM and filesystem analysis, report discrepancies
 */
function validateWithSBOM(
  existingResults: ImagePackagesAnalysis[],
  sbomPackages: AnalyzedPackageWithVersion[],
  options: SBOMMergeOptions,
): MergeResult {
  const mergedResults = [...existingResults];
  const validationIssues: string[] = [];

  // Create maps for comparison
  const existingPackageMap = new Map<string, AnalyzedPackageWithVersion>();
  const existingNameMap = new Map<string, AnalyzedPackageWithVersion>();

  for (const result of existingResults) {
    for (const pkg of result.Analysis) {
      const key = `${pkg.Name}@${pkg.Version}`;
      const nameKey = pkg.Name;
      existingPackageMap.set(key, pkg);
      existingNameMap.set(nameKey, pkg);
    }
  }

  const sbomPackageMap = new Map<string, AnalyzedPackageWithVersion>();
  const sbomNameMap = new Map<string, AnalyzedPackageWithVersion>();

  for (const sbomPkg of sbomPackages) {
    const key = `${sbomPkg.Name}@${sbomPkg.Version}`;
    const nameKey = sbomPkg.Name;
    sbomPackageMap.set(key, sbomPkg);
    sbomNameMap.set(nameKey, sbomPkg);
  }

  // Find exact matches
  let exactMatches = 0;
  for (const key of sbomPackageMap.keys()) {
    if (existingPackageMap.has(key)) {
      exactMatches++;
    }
  }

  // Find version mismatches
  for (const [name, sbomPkg] of sbomNameMap) {
    const existingPkg = existingNameMap.get(name);
    if (existingPkg && existingPkg.Version !== sbomPkg.Version) {
      validationIssues.push(
        `Version mismatch for ${name}: filesystem has ${existingPkg.Version}, SBOM has ${sbomPkg.Version}`,
      );
    }
  }

  // Find packages in SBOM but not in filesystem
  for (const [name, sbomPkg] of sbomNameMap) {
    if (!existingNameMap.has(name)) {
      validationIssues.push(
        `Package ${name}@${sbomPkg.Version} found in SBOM but not in filesystem analysis`,
      );
    }
  }

  // Find packages in filesystem but not in SBOM
  for (const [name, existingPkg] of existingNameMap) {
    if (!sbomNameMap.has(name)) {
      validationIssues.push(
        `Package ${name}@${existingPkg.Version} found in filesystem but not in SBOM`,
      );
    }
  }

  debug(
    `Validation results: ${exactMatches} exact matches, ${validationIssues.length} issues found`,
  );

  // In strict validation mode, throw error if issues found
  if (options.strictValidation && validationIssues.length > 0) {
    throw new Error(
      `SBOM validation failed with ${validationIssues.length} issues`,
    );
  }

  return {
    mergedResults,
    sbomPackagesAdded: 0,
    conflictsResolved: 0,
    validationIssues,
  };
}

/**
 * Utility function to check if two packages are considered the same
 */
export function packagesMatch(
  pkg1: AnalyzedPackageWithVersion,
  pkg2: AnalyzedPackageWithVersion,
  matchStrategy:
    | "exact"
    | "name-only"
    | "name-and-version" = "name-and-version",
): boolean {
  switch (matchStrategy) {
    case "exact":
      return (
        pkg1.Name === pkg2.Name &&
        pkg1.Version === pkg2.Version &&
        pkg1.Source === pkg2.Source
      );
    case "name-only":
      return pkg1.Name === pkg2.Name;
    case "name-and-version":
    default:
      return pkg1.Name === pkg2.Name && pkg1.Version === pkg2.Version;
  }
}
