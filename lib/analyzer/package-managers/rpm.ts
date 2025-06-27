import { formatRpmPackageVersion } from "@snyk/rpm-parser";
import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import { PackageURL } from "packageurl-js";
import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
  OSRelease,
  SourcePackage,
} from "../types";

export function analyze(
  targetImage: string,
  pkgs: PackageInfo[],
  repositories: string[],
  osRelease?: OSRelease,
): Promise<ImagePackagesAnalysis> {
  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Rpm,
    Analysis: pkgs.map((pkgInfo) => {
      const generatedPurl = purl(pkgInfo, repositories, osRelease);
      return {
        Name: pkgInfo.name,
        Version: formatRpmPackageVersion(pkgInfo),
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
        Purl: generatedPurl,
      };
    }),
  });
}

function purl(
  pkg: PackageInfo,
  repos: string[],
  osRelease?: OSRelease,
): string {
  let vendor = "";
  const qualifiers: { [key: string]: string } = {};
  if (pkg.module) {
    const [modName, modVersion] = pkg.module.split(":");
    qualifiers.module = modName + ":" + modVersion;
  }

  if (pkg.sourceRPM) {
    const sourcePackage = parseSourceRPM(pkg.sourceRPM);
    if (sourcePackage) {
      let upstream = sourcePackage.name;
      if (sourcePackage.version) {
        upstream += `@${sourcePackage.version}`;
      }
      qualifiers.upstream = upstream;
    }
  }

  if (repos.length > 0) {
    qualifiers.repositories = repos.join(",");
  }

  if (pkg.epoch) {
    qualifiers.epoch = String(pkg.epoch);
  }

  if (osRelease) {
    qualifiers.distro = `${osRelease.name}-${osRelease.version}`;
    vendor = osRelease.name;
  }

  return new PackageURL(
    AnalysisType.Rpm.toLowerCase(),
    vendor,
    pkg.name,
    formatRpmPackageVersion(pkg),
    Object.keys(qualifiers).length !== 0 ? qualifiers : undefined,
    undefined,
  ).toString();
}

export function parseSourceRPM(
  sourceRPM: string | undefined,
): SourcePackage | undefined {
  if (!sourceRPM || !sourceRPM.endsWith(".src.rpm")) {
    return undefined;
  }

  const baseName = sourceRPM.substring(0, sourceRPM.length - ".src.rpm".length);

  const lastHyphenIdx = baseName.lastIndexOf("-");
  // Ensure there's something after the last hyphen (release) and something before it (name-version)
  if (
    lastHyphenIdx === -1 ||
    lastHyphenIdx === 0 ||
    lastHyphenIdx === baseName.length - 1
  ) {
    return undefined;
  }

  const release = baseName.substring(lastHyphenIdx + 1);
  const nameVersionPart = baseName.substring(0, lastHyphenIdx);

  const secondLastHyphenIdx = nameVersionPart.lastIndexOf("-");
  // Ensure there's something after the second-last hyphen (version) and something before it (name)
  if (
    secondLastHyphenIdx === -1 ||
    secondLastHyphenIdx === 0 ||
    secondLastHyphenIdx === nameVersionPart.length - 1
  ) {
    return undefined;
  }

  const version = nameVersionPart.substring(secondLastHyphenIdx + 1);
  const name = nameVersionPart.substring(0, secondLastHyphenIdx);

  // Final check for empty parts, which could happen with malformed inputs
  // or if hyphens were at the very start/end of segments.
  if (!name || !version || !release) {
    return undefined;
  }

  return {
    name,
    version,
    release,
  };
}

export function mapRpmSqlitePackages(
  targetImage: string,
  rpmPackages: PackageInfo[],
  repositories: string[],
  osRelease?: OSRelease,
): ImagePackagesAnalysis {
  let analysis: AnalyzedPackageWithVersion[] = [];

  if (rpmPackages) {
    analysis = rpmPackages.map((pkg) => {
      const generatedPurl = purl(pkg, repositories, osRelease);

      return {
        Name: pkg.name,
        Version: formatRpmPackageVersion(pkg),
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
        Purl: generatedPurl,
      };
    });
  }
  return {
    Image: targetImage,
    AnalyzeType: AnalysisType.Rpm,
    Analysis: analysis,
  };
}
