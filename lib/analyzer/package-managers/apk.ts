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

export function parseFile(text: string): AnalyzedPackageWithVersion[] {
  const pkgs: AnalyzedPackageWithVersion[] = [];
  let curPkg: AnalyzedPackageWithVersion | null = null;

  for (const line of text.split("\n")) {
    if (line.length < 2) {
      continue;
    }
    const key = line.charAt(0);
    const value = line.substr(2).trim();

    switch (key) {
      case "P": {
        // Package
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
      }
      case "V": // Version
        if (curPkg) {
          curPkg.Version = value;
        }
        break;
      case "p": // Provides
        if (curPkg) {
          for (let name of value.split(" ")) {
            name = name.split("=")[0];
            curPkg.Provides.push(name);
          }
        }
        break;
      case "r": // Depends
      case "D": // Depends
        if (curPkg) {
          for (let name of value.split(" ")) {
            if (name.charAt(0) !== "!") {
              name = name.split("=")[0];
              curPkg.Deps[name] = true;
            }
          }
        }
        break;
      case "o": // Origin
        if (curPkg) {
          curPkg.Source = value;
        }
        break;
    }
  }

  return pkgs;
}
