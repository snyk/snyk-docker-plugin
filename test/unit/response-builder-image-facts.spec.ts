import { AnalysisType } from "../../lib/analyzer/types";
import { buildResponse } from "../../lib/response-builder";

describe("buildResponse — image-level facts on application scan results", () => {
  function analysisWithAppResult(overrides: {
    prettyName?: string;
    platform?: string;
  }) {
    const targetOS = {
      name: "alpine",
      version: "3.19.0",
      prettyName: overrides.prettyName ?? "",
    };
    return {
      depTree: {
        name: "docker-image|alpine-node",
        version: "latest",
        packageFormatVersion: "apk:0.0.1",
        targetOS,
        dependencies: {},
      },
      packageFormat: "apk",
      imageId: "sha256:abc",
      platform: overrides.platform,
      osRelease: targetOS,
      results: [
        {
          Image: "alpine-node",
          AnalyzeType: AnalysisType.Apk,
          Analysis: [],
        },
      ],
      binaries: [],
      imageLayers: [],
      applicationDependenciesScanResults: [
        {
          identity: { type: "npm", targetFile: "/usr/lib/node_modules" },
          facts: [{ type: "testedFiles", data: "/usr/lib/node_modules" }],
        },
      ],
      manifestFiles: [],
      symlinks: {},
    };
  }

  it("attaches imageOsReleasePrettyName and platform to application scan results, matching the OS scan result", async () => {
    const response = await buildResponse(
      analysisWithAppResult({
        prettyName: "Alpine Linux v3.19",
        platform: "linux/amd64",
      }) as any,
      undefined,
      false,
    );

    const osResult = response.scanResults[0];
    const appResult = response.scanResults[1];

    for (const result of [osResult, appResult]) {
      const prettyNameFact = result.facts.find(
        (f) => f.type === "imageOsReleasePrettyName",
      );
      const platformFact = result.facts.find((f) => f.type === "platform");
      expect(prettyNameFact?.data).toBe("Alpine Linux v3.19");
      expect(platformFact?.data).toBe("linux/amd64");
    }

    // Each app result gets its own fact instance pushed once — not shared
    // array references that would duplicate on multiple app results.
    expect(
      appResult.facts.filter((f) => f.type === "imageOsReleasePrettyName"),
    ).toHaveLength(1);
    expect(appResult.facts.filter((f) => f.type === "platform")).toHaveLength(
      1,
    );
  });

  it("omits both facts from application scan results when absent on the image", async () => {
    const response = await buildResponse(
      analysisWithAppResult({}) as any,
      undefined,
      false,
    );

    const appResult = response.scanResults[1];
    expect(
      appResult.facts.find((f) => f.type === "imageOsReleasePrettyName"),
    ).toBeUndefined();
    expect(appResult.facts.find((f) => f.type === "platform")).toBeUndefined();
  });
});
