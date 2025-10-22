import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ChiselPackage,
  ImagePackagesAnalysis,
} from "../types";

/**
 * Analyzes Ubuntu Chisel packages from a Docker image.
 *
 * Chisel is Canonical's tool for creating ultra-minimal Ubuntu container images
 * by installing only specific "slices" of Debian packages rather than full packages.
 * Packages are converted to the standard AnalyzedPackage format and scanned for
 * vulnerabilities as Debian packages.
 *
 * @param targetImage - The Docker image identifier being analyzed
 * @param packages - Array of Chisel packages extracted from the manifest
 * @returns Promise resolving to image package analysis results
 *
 * @see https://documentation.ubuntu.com/chisel/en/latest/
 */
export function analyze(
  targetImage: string,
  packages: ChiselPackage[],
): Promise<ImagePackagesAnalysis> {
  // Convert Chisel packages to standard analyzed package format
  // Note: Chisel packages are treated as Debian packages for vulnerability scanning
  // since they originate from Ubuntu/Debian package archives
  const analysis: AnalyzedPackageWithVersion[] = packages.map((pkg) => ({
    Name: pkg.name,
    Version: pkg.version,
    Source: undefined, // Source package info not available in Chisel manifest
    Provides: [], // Virtual package provides not tracked in Chisel
    Deps: {}, // Dependencies are pre-resolved by Chisel; not exposed in manifest
    AutoInstalled: undefined, // Not applicable - all Chisel packages are explicitly installed
  }));

  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Chisel,
    Analysis: analysis,
  });
}

