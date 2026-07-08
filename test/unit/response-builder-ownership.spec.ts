import { AnalysisType } from "../../lib/analyzer/types";
import { buildResponse } from "../../lib/response-builder";

describe("buildResponse apkPackageOwnership — whole-result (Go)", () => {
  it("attaches an ownership fact to application ScanResults on Wolfi", async () => {
    const response = await buildResponse(
      {
        depTree: {
          name: "docker-image|chainguard-node",
          version: "latest",
          packageFormatVersion: "apk:0.0.1",
          targetOS: {
            name: "wolfi",
            version: "20230201",
            prettyName: "Wolfi",
          },
          dependencies: {},
        },
        packageFormat: "apk",
        imageId: "sha256:abc",
        osRelease: {
          name: "wolfi",
          version: "20230201",
          prettyName: "Wolfi",
        },
        results: [
          {
            Image: "chainguard-node",
            AnalyzeType: AnalysisType.Apk,
            Analysis: [
              {
                Name: "nodejs",
                Version: "20-r1",
                Source: "nodejs",
                Provides: [],
                Deps: {},
                Files: ["/usr/bin/node"],
                Directories: ["/usr/bin"],
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: [],
        applicationDependenciesScanResults: [
          {
            identity: { type: "gomodules", targetFile: "/usr/bin/node" },
            facts: [
              {
                type: "testedFiles",
                data: ["/usr/bin/node"],
              },
            ],
          },
        ],
        manifestFiles: [],
        symlinks: {
          "/bin": "usr/bin",
        },
      },
      undefined,
      false,
    );

    const appResult = response.scanResults[1];
    const ownershipFact = appResult.facts.find(
      (f) => f.type === "apkPackageOwnership",
    );
    expect(ownershipFact).toBeDefined();
    expect(ownershipFact!.data).toMatchObject({
      distroId: "wolfi",
      ownedPackages: [{ apkPackageName: "nodejs", originPackage: "nodejs" }],
    });
  });
});

describe("buildResponse apkPackageOwnership — per-dependency (npm)", () => {
  const npmAnalysis = {
    Image: "chainguard-node",
    AnalyzeType: AnalysisType.Apk,
    Analysis: [
      {
        Name: "npm",
        Version: "10.9.0-r0",
        Source: "npm",
        Provides: [],
        Deps: {},
        Files: [],
        Directories: ["/usr/lib/node_modules/npm/node_modules/brace-expansion"],
      },
    ],
  };

  function wolfiAnalysisWithNpmResult(
    nodeModulesPackagePaths: any[],
    osName = "wolfi",
  ) {
    const targetOS = { name: osName, version: "20230201", prettyName: osName };
    return {
      depTree: {
        name: "docker-image|chainguard-node",
        version: "latest",
        packageFormatVersion: "apk:0.0.1",
        targetOS,
        dependencies: {},
      },
      packageFormat: "apk",
      imageId: "sha256:abc",
      osRelease: targetOS,
      results: [npmAnalysis],
      binaries: [],
      imageLayers: [],
      applicationDependenciesScanResults: [
        {
          identity: { type: "npm", targetFile: "/usr/lib/node_modules" },
          facts: [{ type: "testedFiles", data: "/usr/lib/node_modules" }],
          // Internal carrier: install dirs the node scanner recorded, never a fact.
          nodeModulesPackagePaths,
        },
      ],
      manifestFiles: [],
      symlinks: {},
    };
  }

  it("attaches a per-dependency ownership fact and never leaks the install dirs", async () => {
    const response = await buildResponse(
      wolfiAnalysisWithNpmResult([
        {
          name: "brace-expansion",
          version: "2.0.1",
          installDir: "/usr/lib/node_modules/npm/node_modules/brace-expansion",
        },
      ]) as any,
      undefined,
      false,
    );

    const appResult = response.scanResults[1];
    const ownershipFact = appResult.facts.find(
      (f) => f.type === "apkPackageOwnership",
    );
    expect(ownershipFact).toBeDefined();
    expect(ownershipFact!.data).toMatchObject({
      distroId: "wolfi",
      ownedPackages: [
        {
          name: "brace-expansion",
          version: "2.0.1",
          originPackage: "npm",
          apkPackageName: "npm",
        },
      ],
    });

    // The internal install-dir data must never reach the public ScanResult.
    expect((appResult as any).nodeModulesPackagePaths).toBeUndefined();
    expect(
      appResult.facts.find((f) => f.type === "nodeModulesPackagePaths"),
    ).toBeUndefined();
  });

  it("emits no ownership fact when nothing is owned", async () => {
    const response = await buildResponse(
      wolfiAnalysisWithNpmResult([
        {
          name: "left-pad",
          version: "1.3.0",
          installDir: "/usr/local/lib/node_modules/left-pad",
        },
      ]) as any,
      undefined,
      false,
    );

    const appResult = response.scanResults[1];
    expect(
      appResult.facts.find((f) => f.type === "apkPackageOwnership"),
    ).toBeUndefined();
    expect((appResult as any).nodeModulesPackagePaths).toBeUndefined();
  });

  it("does no ownership work on non-Chainguard distros and never leaks install dirs", async () => {
    const response = await buildResponse(
      wolfiAnalysisWithNpmResult(
        [
          {
            name: "brace-expansion",
            version: "2.0.1",
            installDir:
              "/usr/lib/node_modules/npm/node_modules/brace-expansion",
          },
        ],
        "alpine",
      ) as any,
      undefined,
      false,
    );

    const appResult = response.scanResults[1];
    // Gated off on non-Chainguard: no ownership fact even though the dir is owned.
    expect(
      appResult.facts.find((f) => f.type === "apkPackageOwnership"),
    ).toBeUndefined();
    expect((appResult as any).nodeModulesPackagePaths).toBeUndefined();
  });
});
