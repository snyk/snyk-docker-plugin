import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../../types";

// Supported hardened image vendor prefixes
const VENDOR_PREFIXES = ["dhi"] as const;
type VendorPrefix = (typeof VENDOR_PREFIXES)[number];

const VENDOR_PREFIX_PATTERN = new RegExp(`^(${VENDOR_PREFIXES.join("|")})/`);

export function analyze(
  targetImage: string,
  spdxFileContents: string[],
): Promise<ImagePackagesAnalysis> {
  const analyzedPackages: AnalyzedPackageWithVersion[] = [];

  for (const fileContent of spdxFileContents) {
    const currentPackages = parseSpdxFile(fileContent);
    analyzedPackages.push(...currentPackages);
  }

  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Spdx,
    Analysis: analyzedPackages,
  });
}

function parseSpdxFile(text: string): AnalyzedPackageWithVersion[] {
  const pkgs: AnalyzedPackageWithVersion[] = [];

  try {
    const spdxDoc = JSON.parse(text);

    if (!spdxDoc.packages || !Array.isArray(spdxDoc.packages)) {
      return pkgs;
    }

    // Usually packages.length === 1, but iterate anyway for safety
    for (const pkg of spdxDoc.packages) {
      const analyzedPkg = parseSpdxLine(pkg);
      pkgs.push(analyzedPkg);
    }
  } catch (err) {
    console.error(`Failed to parse SPDX: ${err.message}`);
  }

  return pkgs;
}

function parseSpdxLine(pkg: any): AnalyzedPackageWithVersion {
  const { vendor, cleanName } = parseVendorName(pkg.name);
  const version = pkg.versionInfo;
  const purl = extractPurl(pkg) || (vendor ? createPurl(cleanName, version, vendor) : undefined);

  return {
    Name: cleanName,
    Version: version,
    Source: undefined,
    Provides: [],
    Deps: {},
    AutoInstalled: undefined,
    Purl: purl,
  };
}

function parseVendorName(name: string): { vendor: VendorPrefix | undefined; cleanName: string } {
  const match = name.match(VENDOR_PREFIX_PATTERN);
  if (match) {
    return {
      vendor: match[1] as VendorPrefix,
      cleanName: name.replace(VENDOR_PREFIX_PATTERN, ""),
    };
  }
  return { vendor: undefined, cleanName: name };
}

function extractPurl(pkg: any): string | undefined {
  if (!pkg.externalRefs || !Array.isArray(pkg.externalRefs)) {
    return undefined;
  }

  const purlRef = pkg.externalRefs.find((ref) => ref.referenceType === "purl");

  return purlRef?.referenceLocator;
}

function createPurl(name: string, version: string, vendor: VendorPrefix): string {
  return `pkg:${vendor}/${name}@${version}`;
}
