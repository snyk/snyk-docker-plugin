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
  // Absolute path of the most recent F: record; "" until one is seen.
  let currentDir = "";

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
          Files: [],
          Directories: [],
        };
        pkgs.push(curPkg);
        currentDir = "";
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
      case "F": {
        // Directory for subsequent R:/M: file-list records, root-relative
        // like "usr/lib"
        if (!curPkg) {
          break;
        }
        currentDir = value ? "/" + value : "";
        if (currentDir && !curPkg.Directories!.includes(currentDir)) {
          curPkg.Directories!.push(currentDir);
        }
        break;
      }
      case "R": {
        // File name relative to the current F: directory
        if (!curPkg || !currentDir) {
          break;
        }
        curPkg.Files!.push(`${currentDir}/${value}`);
        break;
      }
      case "M": {
        // Directory metadata for the current F: directory
        if (!curPkg || !currentDir) {
          break;
        }
        if (!curPkg.Directories!.includes(currentDir)) {
          curPkg.Directories!.push(currentDir);
        }
        break;
      }
    }
  }

  return pkgs;
}
