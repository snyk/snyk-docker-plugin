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
  let dirStack: string[] = [];

  for (const line of text.split("\n")) {
    if (line.length < 2) {
      continue;
    }
    const key = line.charAt(0);
    const value = line.substr(2).trim();

    switch (key) {
      case "P": {
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
        dirStack = [];
        break;
      }
      case "V":
        if (curPkg) {
          curPkg.Version = value;
        }
        break;
      case "p":
        if (curPkg) {
          for (let name of value.split(" ")) {
            name = name.split("=")[0];
            curPkg.Provides.push(name);
          }
        }
        break;
      case "r":
      case "D":
        if (curPkg) {
          for (let name of value.split(" ")) {
            if (name.charAt(0) !== "!") {
              name = name.split("=")[0];
              curPkg.Deps[name] = true;
            }
          }
        }
        break;
      case "o":
        if (curPkg) {
          curPkg.Source = value;
        }
        break;
      case "F": {
        if (!curPkg) {
          break;
        }
        dirStack = value.split("/").filter(Boolean);
        const dirPath = stackToAbsolutePath(dirStack);
        if (!curPkg.Directories!.includes(dirPath)) {
          curPkg.Directories!.push(dirPath);
        }
        break;
      }
      case "R": {
        if (!curPkg || dirStack.length === 0) {
          break;
        }
        const filePath = stackToAbsolutePath([...dirStack, value]);
        curPkg.Files!.push(filePath);
        break;
      }
      case "M": {
        if (!curPkg || dirStack.length === 0) {
          break;
        }
        const dirPath = stackToAbsolutePath(dirStack);
        if (!curPkg.Directories!.includes(dirPath)) {
          curPkg.Directories!.push(dirPath);
        }
        break;
      }
    }
  }

  return pkgs;
}

function stackToAbsolutePath(stack: string[]): string {
  return "/" + stack.join("/");
}
