import { AnalysisType } from "../../lib/analyzer/types";
import { buildResponse } from "../../lib/response-builder";

describe("buildResponse apkPackageOwnership", () => {
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
      originPackage: "nodejs",
      packageName: "nodejs",
    });
  });
});
