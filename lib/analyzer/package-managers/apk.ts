import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImagePackagesAnalysis,
} from "../types";

export function analyze(
  targetImage: string,
  apkDbFileContent: string,
): Promise<ImagePackagesAnalysis> {
  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Apk,
    Analysis: parseFile(apkDbFileContent),
  });
}

function parseFile(text: string): AnalyzedPackageWithVersion[] {
  const pkgs: AnalyzedPackageWithVersion[] = [];
  let curPkg: any = null;
  for (const line of text.split("\n")) {
    curPkg = parseLine(line, curPkg, pkgs);
  }
  return pkgs;
}

function parseLine(
  text: string,
  curPkg: AnalyzedPackageWithVersion,
  pkgs: AnalyzedPackageWithVersion[],
) {
  const key = text.charAt(0);
  const value = text.substr(2).trim();
  switch (key) {
    case "P": // Package
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
    case "V": // Version
      curPkg.Version = value;
      break;
    case "p": // Provides
      for (let name of value.split(" ")) {
        name = name.split("=")[0];
        curPkg.Provides.push(name);
      }
      break;
    case "r": // Depends
    case "D": // Depends
      // tslint:disable-next-line:no-duplicate-variable
      for (let name of value.split(" ")) {
        if (name.charAt(0) !== "!") {
          name = name.split("=")[0];
          curPkg.Deps[name] = true;
        }
      }
      break;
    case "o": // Origin
      curPkg.Source = value;
      break;
  }
  return curPkg;
}
