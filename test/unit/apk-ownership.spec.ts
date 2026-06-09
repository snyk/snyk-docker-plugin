import {
  buildApkPathIndex,
  resolveApkOwnership,
  resolveOwnerForEvidencePath,
} from "../../lib/analyzer/package-managers/apk-ownership";
import { canonicalizePath } from "../../lib/analyzer/package-managers/path-canonicalization";
import { AnalyzedPackageWithVersion } from "../../lib/analyzer/types";

function makePackage(
  name: string,
  version: string,
  origin: string,
  files: string[],
  directories: string[],
): AnalyzedPackageWithVersion {
  return {
    Name: name,
    Version: version,
    Source: origin,
    Provides: [],
    Deps: {},
    Files: files,
    Directories: directories,
  };
}

describe("apk-ownership", () => {
  const symlinkGraph = new Map<string, string>([["/bin", "usr/bin"]]);

  it("resolves exact file owners via O(1) lookup", () => {
    const packages = [
      makePackage("git", "2.43-r1", "git", ["/usr/bin/git"], ["/usr/bin"]),
      makePackage("git-base", "2.43-r1", "git", [], ["/usr", "/usr/bin"]),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);

    const match = resolveOwnerForEvidencePath(
      "/usr/bin/git",
      index,
      symlinkGraph,
    );
    expect(match?.owner.Name).toBe("git");
    expect(match?.matchKind).toBe("exact");
  });

  it("canonicalizes evidence paths before matching APK file owners", () => {
    const packages = [
      makePackage("nodejs", "20-r1", "nodejs", ["/usr/bin/node"], ["/usr/bin"]),
    ];
    const ownership = resolveApkOwnership(
      ["/bin/node"],
      packages,
      { name: "wolfi", version: "20230201", prettyName: "Wolfi" },
      symlinkGraph,
    );

    expect(ownership).toEqual({
      distroId: "wolfi",
      packageName: "nodejs",
      packageVersion: "20-r1",
      originPackage: "nodejs",
      evidencePaths: ["/bin/node"],
    });
  });

  it("returns undefined when evidence is not owned by any APK package", () => {
    const packages = [
      makePackage("bash", "5.2-r1", "bash", ["/bin/bash"], ["/bin"]),
    ];
    const ownership = resolveApkOwnership(
      ["/opt/custom/app"],
      packages,
      { name: "chainguard", version: "20230214", prettyName: "Chainguard" },
      symlinkGraph,
    );

    expect(ownership).toBeUndefined();
  });

  it("does not run ownership resolution for non-Chainguard distros", () => {
    const packages = [
      makePackage("nodejs", "20-r1", "nodejs", ["/usr/bin/node"], ["/usr/bin"]),
    ];
    const ownership = resolveApkOwnership(
      ["/usr/bin/node"],
      packages,
      { name: "alpine", version: "3.19", prettyName: "Alpine" },
      symlinkGraph,
    );

    expect(ownership).toBeUndefined();
  });

  it("uses directory prefix only when exact file match is unavailable", () => {
    const packages = [
      makePackage("git-base", "2.43-r1", "git", [], ["/usr", "/usr/libexec"]),
      makePackage(
        "git",
        "2.43-r1",
        "git",
        ["/usr/libexec/git-core/git"],
        ["/usr/libexec"],
      ),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const exact = resolveOwnerForEvidencePath(
      "/usr/libexec/git-core/git",
      index,
      symlinkGraph,
    );
    expect(exact?.owner.Name).toBe("git");
    expect(exact?.matchKind).toBe("exact");
  });

  it("canonicalizes APK declared paths consistently", () => {
    const packages = [
      makePackage("nodejs", "20-r1", "nodejs", ["/usr/bin/node"], []),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const canonicalApkPath = canonicalizePath("/usr/bin/node", symlinkGraph);
    expect(index.exactFileOwners.get(canonicalApkPath)?.[0].Name).toBe(
      "nodejs",
    );
  });
});
