import { AnalyzerPkg } from "./types";
export { analyze };

const APK_DB_INSTALLED = "lib/apk/db/installed";

const APK_PKGPATHS = [APK_DB_INSTALLED];

export { APK_PKGPATHS };

async function analyze(
  targetImage: string,
  pkgFiles: { [key: string]: string },
) {
  const dbFile = pkgFiles[APK_DB_INSTALLED];
  const pkgs = dbFile ? parseFile(dbFile) : [];
  return {
    Image: targetImage,
    AnalyzeType: "Apk",
    Analysis: pkgs,
  };
}

function parseFile(text: string) {
  const pkgs: AnalyzerPkg[] = [];
  let curPkg: any = null;
  for (const line of text.split("\n")) {
    curPkg = parseLine(line, curPkg, pkgs);
  }
  return pkgs;
}

function parseLine(text: string, curPkg: AnalyzerPkg, pkgs: AnalyzerPkg[]) {
  const key = text.charAt(0);
  const value = text.substr(2);
  switch (key) {
    case "P": // Package
      curPkg = {
        Name: value,
        Version: undefined,
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
  }
  return curPkg;
}
