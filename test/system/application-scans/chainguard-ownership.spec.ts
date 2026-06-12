import { scan } from "../../../lib/index";

describe("chainguard app ownership", () => {
  afterAll(async () => {
    // Best-effort cleanup if the image was pulled during the test.
    try {
      const { execute } = await import("../../../lib/sub-process");
      await execute("docker", [
        "image",
        "rm",
        "chainguard/bash@sha256:642933df66209814502599053ca3dfa97cccf847badc4219d2b1fd6565f6559a",
      ]);
    } catch {
      // ignore teardown errors
    }
  });

  it("does not attach apkPackageOwnership on OS-only Chainguard images", async () => {
    const image =
      "chainguard/bash@sha256:642933df66209814502599053ca3dfa97cccf847badc4219d2b1fd6565f6559a";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    const appResults = pluginResult.scanResults.slice(1);
    const ownershipFacts = appResults.flatMap((result) =>
      result.facts.filter((fact) => fact.type === "apkPackageOwnership"),
    );
    expect(ownershipFacts).toHaveLength(0);
  });
});
