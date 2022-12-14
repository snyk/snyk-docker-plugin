import { formatRpmPackageVersion } from "@snyk/rpm-parser";
import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../types";

export function analyze(
  targetImage: string,
  pkgs: PackageInfo[],
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
      };
    }),
  });
}

export function mapRpmSqlitePackages(
  targetImage: string,
  rpmPackages: PackageInfo[],
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
      };
    });
  }
  return {
    Image: targetImage,
    AnalyzeType: AnalysisType.Rpm,
    Analysis: analysis,
  };
}
