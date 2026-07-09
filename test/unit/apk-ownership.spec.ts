import {
  buildApkPathIndex,
  isChainguardDistro,
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

const wolfi = { name: "wolfi", version: "20230201", prettyName: "Wolfi" };

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
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [{ evidencePaths: ["/bin/node"] }],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toEqual({
      distroId: "wolfi",
      ownedPackages: [
        {
          evidencePaths: ["/bin/node"],
          apkPackageName: "nodejs",
          apkPackageVersion: "20-r1",
          originPackage: "nodejs",
        },
      ],
    });
  });

  it("returns undefined when evidence is not owned by any APK package", () => {
    const packages = [
      makePackage("bash", "5.2-r1", "bash", ["/bin/bash"], ["/bin"]),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [{ evidencePaths: ["/opt/custom/app"] }],
      index,
      symlinkGraph,
      { name: "chainguard", version: "20230214", prettyName: "Chainguard" },
    );

    expect(ownership).toBeUndefined();
  });

  it("does not run ownership resolution for non-Chainguard distros", () => {
    const packages = [
      makePackage("nodejs", "20-r1", "nodejs", ["/usr/bin/node"], ["/usr/bin"]),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [{ evidencePaths: ["/usr/bin/node"] }],
      index,
      symlinkGraph,
      { name: "alpine", version: "3.19", prettyName: "Alpine" },
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

  it("omits a candidate when only some of its evidence paths are owned", () => {
    // Chainguard spec: a candidate's evidence paths must be wholly contained in
    // the owning package's declared paths; a partially-owned unit keeps findings.
    const packages = [
      makePackage("nodejs", "20-r1", "nodejs", ["/usr/bin/node"], ["/usr/bin"]),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [{ evidencePaths: ["/usr/bin/node", "/opt/custom/app.jar"] }],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toBeUndefined();
  });

  it("prefers an exactly matched owner over a directory-matched owner", () => {
    const packages = [
      makePackage(
        "gradle",
        "8.5-r0",
        "gradle",
        ["/usr/share/java/gradle/lib/gradle.jar"],
        ["/usr/share/java/gradle"],
      ),
      makePackage(
        "java-common",
        "1-r0",
        "java-common",
        [],
        ["/usr/share/java"],
      ),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: [
            "/usr/share/java/gradle/lib/gradle.jar", // exact: gradle
            "/usr/share/java/other.jar", // directory: java-common
          ],
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership?.ownedPackages[0].apkPackageName).toBe("gradle");
  });

  it("returns undefined when different owners each have exact matches", () => {
    const packages = [
      makePackage("pkg-a", "1-r0", "pkg-a", ["/usr/bin/a"], ["/usr/bin"]),
      makePackage("pkg-b", "1-r0", "pkg-b", ["/usr/bin/some-b"], ["/usr/bin"]),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [{ evidencePaths: ["/usr/bin/a", "/usr/bin/some-b"] }],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toBeUndefined();
  });

  it("prefers the deepest directory match when no exact matches exist", () => {
    const packages = [
      makePackage("python", "3.12-r1", "python", [], ["/usr/lib/python3.12"]),
      makePackage(
        "py-foo",
        "1.0-r0",
        "py-foo",
        [],
        ["/usr/lib/python3.12/site-packages/foo"],
      ),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: [
            "/usr/lib/python3.12/site-packages/foo/mod.py", // directory: py-foo (deeper)
            "/usr/lib/python3.12/abc.py", // directory: python (shallower)
          ],
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership?.ownedPackages[0].apkPackageName).toBe("py-foo");
  });

  it("returns undefined when one directory is declared by multiple packages", () => {
    // On Chainguard node images, /usr/lib/node_modules is declared by both
    // node-gyp and npm. Neither wholly owns it, so ownership is ambiguous and
    // must fail closed rather than attributing the whole tree to an arbitrary one.
    const packages = [
      makePackage(
        "node-gyp",
        "13.0.0-r0",
        "node-gyp",
        [],
        ["/usr/lib/node_modules"],
      ),
      makePackage("npm", "10.9.0-r0", "npm", [], ["/usr/lib/node_modules"]),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [{ evidencePaths: ["/usr/lib/node_modules"] }],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toBeUndefined();
  });

  it("returns undefined for a directory-depth tie between different owners", () => {
    const packages = [
      makePackage("pkg-a", "1-r0", "pkg-a", [], ["/usr/lib/a"]),
      makePackage("pkg-b", "1-r0", "pkg-b", [], ["/usr/lib/b"]),
    ];
    const index = buildApkPathIndex(packages, symlinkGraph);
    const ownership = resolveApkOwnership(
      [{ evidencePaths: ["/usr/lib/a/x.so", "/usr/lib/b/y.so"] }],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toBeUndefined();
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

  it("matches the distro id case-insensitively", () => {
    expect(
      isChainguardDistro({
        name: "Wolfi",
        version: "20230201",
        prettyName: "",
      }),
    ).toBe(true);
    expect(
      isChainguardDistro({
        name: "CHAINGUARD",
        version: "20230214",
        prettyName: "",
      }),
    ).toBe(true);
    expect(
      isChainguardDistro({ name: "alpine", version: "3.19", prettyName: "" }),
    ).toBe(false);
    expect(isChainguardDistro(undefined)).toBe(false);
  });
});

describe("resolveApkOwnership per-package (npm)", () => {
  const symlinkGraph = new Map<string, string>();

  // The npm apk package bundles its own dependencies under its subtree, so each
  // bundled package's directory is owned even though the node_modules root is not.
  const npmPackage = makePackage(
    "npm",
    "10.9.0-r0",
    "npm",
    [],
    [
      "/usr/lib/node_modules/npm",
      "/usr/lib/node_modules/npm/node_modules/brace-expansion",
    ],
  );

  it("resolves a coordinate-bearing candidate to its owning APK origin", () => {
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: [
            "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          ],
          name: "brace-expansion",
          version: "2.0.1",
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toEqual({
      distroId: "wolfi",
      ownedPackages: [
        {
          evidencePaths: [
            "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          ],
          apkPackageName: "npm",
          apkPackageVersion: "10.9.0-r0",
          originPackage: "npm",
          name: "brace-expansion",
          version: "2.0.1",
        },
      ],
    });
  });

  it("resolves each candidate independently, omitting unowned ones", () => {
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: [
            "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          ],
          name: "brace-expansion",
          version: "2.0.1",
        },
        {
          evidencePaths: ["/usr/local/lib/node_modules/left-pad"],
          name: "left-pad",
          version: "1.3.0",
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership?.ownedPackages.map((p) => p.name)).toEqual([
      "brace-expansion",
    ]);
  });

  it("does not resolve ownership for the shared node_modules root", () => {
    const sharedRoot = [
      npmPackage,
      makePackage(
        "node-gyp",
        "13.0.0-r0",
        "node-gyp",
        [],
        ["/usr/lib/node_modules"],
      ),
      makePackage("npm", "10.9.0-r0", "npm", [], ["/usr/lib/node_modules"]),
    ];
    const index = buildApkPathIndex(sharedRoot, symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: ["/usr/lib/node_modules"],
          name: "root",
          version: "0",
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toBeUndefined();
  });

  it("dedupes a coordinate by name@version, keeping the owned occurrence", () => {
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        // unowned copy
        {
          evidencePaths: ["/app/node_modules/brace-expansion"],
          name: "brace-expansion",
          version: "2.0.1",
        },
        // owned copy
        {
          evidencePaths: [
            "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          ],
          name: "brace-expansion",
          version: "2.0.1",
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership?.ownedPackages).toHaveLength(1);
    expect(ownership?.ownedPackages[0].originPackage).toBe("npm");
  });

  it("dedupes a coordinate when the owned occurrence is resolved first", () => {
    // Owned copy sorts first ("/usr" < "/zzz"), so it fills `seen` and the later
    // duplicate hits the seen.has skip — the reverse order of the test above.
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: [
            "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          ],
          name: "brace-expansion",
          version: "2.0.1",
        },
        {
          evidencePaths: ["/zzz/node_modules/brace-expansion"],
          name: "brace-expansion",
          version: "2.0.1",
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership?.ownedPackages).toHaveLength(1);
    expect(ownership?.ownedPackages[0].originPackage).toBe("npm");
  });

  it("deterministically resolves a coordinate bundled by two different apk packages", () => {
    // Same coordinate under two apk packages: the localeCompare sort picks the
    // lexicographically-first evidence path ("aaa" < "npm") regardless of order.
    const aaaPackage = makePackage(
      "aaa",
      "1.0.0-r0",
      "aaa",
      [],
      ["/usr/lib/node_modules/aaa/node_modules/brace-expansion"],
    );
    const index = buildApkPathIndex([npmPackage, aaaPackage], symlinkGraph);

    const candidates = [
      {
        evidencePaths: [
          "/usr/lib/node_modules/npm/node_modules/brace-expansion",
        ],
        name: "brace-expansion",
        version: "2.0.1",
      },
      {
        evidencePaths: [
          "/usr/lib/node_modules/aaa/node_modules/brace-expansion",
        ],
        name: "brace-expansion",
        version: "2.0.1",
      },
    ];

    const ownership = resolveApkOwnership(
      candidates,
      index,
      symlinkGraph,
      wolfi,
    );
    const reversed = resolveApkOwnership(
      [...candidates].reverse(),
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership?.ownedPackages).toHaveLength(1);
    expect(ownership?.ownedPackages[0].originPackage).toBe("aaa");
    // Input order must not change the winner.
    expect(reversed?.ownedPackages[0].originPackage).toBe("aaa");
  });

  it("skips a candidate whose evidencePaths is empty", () => {
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        { evidencePaths: [], name: "phantom", version: "0.0.0" },
        {
          evidencePaths: [
            "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          ],
          name: "brace-expansion",
          version: "2.0.1",
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership?.ownedPackages.map((p) => p.name)).toEqual([
      "brace-expansion",
    ]);
  });

  it("returns undefined for non-Chainguard distros", () => {
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: [
            "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          ],
          name: "brace-expansion",
          version: "2.0.1",
        },
      ],
      index,
      symlinkGraph,
      { name: "alpine", version: "3.19", prettyName: "Alpine" },
    );

    expect(ownership).toBeUndefined();
  });

  it("returns undefined when no candidate is owned", () => {
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    const ownership = resolveApkOwnership(
      [
        {
          evidencePaths: ["/app/left-pad"],
          name: "left-pad",
          version: "1.3.0",
        },
      ],
      index,
      symlinkGraph,
      wolfi,
    );

    expect(ownership).toBeUndefined();
  });

  it("returns undefined for empty input", () => {
    const index = buildApkPathIndex([npmPackage], symlinkGraph);
    expect(resolveApkOwnership([], index, symlinkGraph, wolfi)).toBeUndefined();
  });
});
