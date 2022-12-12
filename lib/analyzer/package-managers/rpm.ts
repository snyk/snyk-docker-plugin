import { formatRpmPackageVersion } from "@snyk/rpm-parser";
import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import { PackageURL } from "packageurl-js";
import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../types";

export function analyze(
  targetImage: string,
  pkgs: PackageInfo[],
  repositories: string[],
): Promise<ImagePackagesAnalysis> {
  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Rpm,
    Analysis: pkgs.map((pkgInfo) => {
      return {
        Name: pkgInfo.name,
        Version: formatRpmPackageVersion(pkgInfo),
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
        Purl: purl(pkgInfo, repositories),
      };
    }),
  });
}

function purl(pkg: PackageInfo, repos: string[]): string {
  const qualifiers: { [key: string]: string } = {};
  if (pkg.module) {
    const [modName, modVersion] = pkg.module.split(":");
    qualifiers.module = modName + ":" + modVersion;
  }

  if (repos.length > 0) {
    qualifiers.repositories = repos.join(",");
  }

  if (pkg.epoch) {
    qualifiers.epoch = String(pkg.epoch);
  }

  return new PackageURL(
    AnalysisType.Rpm.toLowerCase(),
    "", // would be the Vendor according to the purl rpm spec
    pkg.name,
    formatRpmPackageVersion(pkg),
    // make sure that we pass in undefined if there are no qualifiers, because
    // the packageurl-js library doesn't handle that properly...
    Object.keys(qualifiers).length !== 0 ? qualifiers : undefined,
    undefined,
  ).toString();
}

export function mapRpmSqlitePackages(
  targetImage: string,
  rpmPackages: PackageInfo[],
  repositories: string[],
): ImagePackagesAnalysis {
  let analysis: AnalyzedPackageWithVersion[] = [];

  if (rpmPackages) {
    analysis = rpmPackages.map((pkg) => {
      return {
        Name: pkg.name,
        Version: formatRpmPackageVersion(pkg),
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
        Purl: purl(pkg, repositories),
      };
    });
  }
  return {
    Image: targetImage,
    AnalyzeType: AnalysisType.Rpm,
    Analysis: analysis,
  };
}
