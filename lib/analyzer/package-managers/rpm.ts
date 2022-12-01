import { formatRpmPackageVersion } from "@snyk/rpm-parser";
import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../types";

export function analyze(
  targetImage: string,
  rpmDbFilecontent: string,
): Promise<ImagePackagesAnalysis> {
  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Rpm,
    Analysis: parseOutput(rpmDbFilecontent),
  });
}

function parseOutput(output: string) {
  const pkgs: AnalyzedPackageWithVersion[] = [];
  for (const line of output.split("\n")) {
    parseLine(line, pkgs);
  }
  return pkgs;
}

function parseLine(text: string, pkgs: AnalyzedPackageWithVersion[]) {
  const [name, version, size] = text.split("\t");
  if (name && version && size) {
    const pkg: AnalyzedPackageWithVersion = {
      Name: name,
      Version: version,
      Source: undefined,
      Provides: [],
      Deps: {},
      AutoInstalled: undefined,
    };
    pkgs.push(pkg);
  }
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
