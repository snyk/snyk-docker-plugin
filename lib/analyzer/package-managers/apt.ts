import {
  AnalysisType,
  AnalyzedPackage,
  AnalyzedPackageWithVersion,
  IAptFiles,
  ImagePackagesAnalysis,
} from "../types";

export function analyze(
  targetImage: string,
  aptFiles: IAptFiles,
): Promise<ImagePackagesAnalysis> {
  const pkgs = parseDpkgFile(aptFiles.dpkgFile);

  if (aptFiles.extFile) {
    setAutoInstalledPackages(aptFiles.extFile, pkgs);
  }

  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Apt,
    Analysis: pkgs,
  });
}

export function analyzeDistroless(
  targetImage: string,
  aptFiles: string[],
): Promise<ImagePackagesAnalysis> {
  const analyzedPackages: AnalyzedPackageWithVersion[] = [];

  for (const fileContent of aptFiles) {
    const currentPackages = parseDpkgFile(fileContent);
    analyzedPackages.push(...currentPackages);
  }

  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Apt,
    Analysis: analyzedPackages,
  });
}

function parseDpkgFile(text: string): AnalyzedPackageWithVersion[] {
  const pkgs: AnalyzedPackageWithVersion[] = [];
  let curPkg: any = null;
  for (const line of text.split("\n")) {
    curPkg = parseDpkgLine(line, curPkg, pkgs);
  }
  return pkgs;
}

function parseDpkgLine(
  text: string,
  curPkg: AnalyzedPackageWithVersion,
  pkgs: AnalyzedPackageWithVersion[],
): AnalyzedPackage {
  const [key, value] = text.split(": ");
  switch (key) {
    case "Package":
      curPkg = {
        Name: value,
        Version: "",
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
      };
      pkgs.push(curPkg);
      break;
    case "Version":
      curPkg.Version = value;
      break;
    case "Source":
      curPkg.Source = value.trim().split(" ")[0];
      break;
    case "Provides":
      for (let name of value.split(",")) {
        name = name.trim().split(" ")[0];
        curPkg.Provides.push(name);
      }
      break;
    case "Pre-Depends":
    case "Depends":
      for (const depElem of value.split(",")) {
        for (let name of depElem.split("|")) {
          name = name.trim().split(" ")[0];
          curPkg.Deps[name] = true;
        }
      }
      break;
  }
  return curPkg;
}

function setAutoInstalledPackages(text: string, pkgs: AnalyzedPackage[]) {
  const autoPkgs = parseExtFile(text);
  for (const pkg of pkgs) {
    if (autoPkgs[pkg.Name]) {
      pkg.AutoInstalled = true;
    }
  }
}

interface PkgMap {
  [name: string]: boolean;
}

function parseExtFile(text: string) {
  const pkgMap: PkgMap = {};
  let curPkgName: any = null;
  for (const line of text.split("\n")) {
    curPkgName = parseExtLine(line, curPkgName, pkgMap);
  }
  return pkgMap;
}

function parseExtLine(text: string, curPkgName: string, pkgMap: PkgMap) {
  const [key, value] = text.split(": ");
  switch (key) {
    case "Package":
      curPkgName = value;
      break;
    case "Auto-Installed":
      if (parseInt(value, 10) === 1) {
        pkgMap[curPkgName] = true;
      }
      break;
  }
  return curPkgName;
}
