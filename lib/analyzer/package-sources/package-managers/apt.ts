import { PackageURL } from "packageurl-js";
import {
  AnalysisType,
  AnalyzedPackage,
  AnalyzedPackageWithVersion,
  IAptFiles,
  ImagePackagesAnalysis,
  OSRelease,
} from "../../types";

export function analyze(
  targetImage: string,
  aptFiles: IAptFiles,
  osRelease?: OSRelease,
): Promise<ImagePackagesAnalysis> {
  const pkgs = parseDpkgFile(aptFiles.dpkgFile, osRelease);

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
  osRelease?: OSRelease,
): Promise<ImagePackagesAnalysis> {
  const analyzedPackages: AnalyzedPackageWithVersion[] = [];

  for (const fileContent of aptFiles) {
    const currentPackages = parseDpkgFile(fileContent, osRelease);
    analyzedPackages.push(...currentPackages);
  }

  return Promise.resolve({
    Image: targetImage,
    AnalyzeType: AnalysisType.Apt,
    Analysis: analyzedPackages,
  });
}

function parseDpkgFile(
  text: string,
  osRelease?: OSRelease,
): AnalyzedPackageWithVersion[] {
  const pkgs: AnalyzedPackageWithVersion[] = [];
  let curPkg: AnalyzedPackageWithVersion | null = null;
  for (const line of text.split("\n")) {
    curPkg = parseDpkgLine(line, curPkg!, pkgs);
    if (curPkg) {
      curPkg.Purl = purl(curPkg, osRelease);
    }
  }
  return pkgs;
}

const debianCodenames = new Map<string, string>([
  ["8", "jessie"],
  ["9", "stretch"],
  ["10", "buster"],
  ["11", "bullseye"],
  ["12", "bookworm"],
  ["13", "trixie"],
  ["unstable", "sid"],
]);

export function purl(
  curPkg: AnalyzedPackageWithVersion,
  osRelease?: OSRelease,
): string | undefined {
  let vendor = "";
  if (!curPkg.Name || !curPkg.Version) {
    return undefined;
  }

  const qualifiers: { [key: string]: string } = {};
  if (curPkg.Source && curPkg.SourceVersion) {
    qualifiers.upstream = `${curPkg.Source}@${curPkg.SourceVersion}`;
  } else if (curPkg.Source) {
    qualifiers.upstream = curPkg.Source;
  }

  if (osRelease) {
    const codenameOrVersion =
      debianCodenames.get(osRelease.version) ?? osRelease.version;
    qualifiers.distro = `${osRelease.name}-${codenameOrVersion}`;
    vendor = osRelease.name;
  }

  return new PackageURL(
    "deb",
    vendor,
    curPkg.Name,
    curPkg.Version,
    // make sure that we pass in undefined if there are no qualifiers, because
    // the packageurl-js library doesn't handle that properly...
    Object.keys(qualifiers).length !== 0 ? qualifiers : undefined,
    undefined,
  ).toString();
}

function parseDpkgLine(
  text: string,
  curPkg: AnalyzedPackageWithVersion,
  pkgs: AnalyzedPackageWithVersion[],
): AnalyzedPackageWithVersion {
  const [key, value] = text.split(": ");
  switch (key) {
    case "Package":
      curPkg = {
        Name: value,
        Version: "",
        Source: undefined,
        SourceVersion: undefined,
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
      /**
       * The value may look something like this:
       * libgcc6 (1.3.0-b1)
       * <name> (<version>)
       *
       * For example, Syft matches these values with a regex:
       * https://github.com/anchore/syft/blob/1764e1c3f6bd66781f8350d957a1f95e4d9ad3de/syft/pkg/cataloger/deb/parse_dpkg_db.go#L169-L173
       */
      const parts = value.split(" ");
      curPkg.Source = parts[0];
      if (parts.length > 1) {
        curPkg.SourceVersion = parts[1]
          .trim()
          .replace("(", "")
          .replace(")", "");
      }
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
