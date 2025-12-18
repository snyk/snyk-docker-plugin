import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("handles bad input being provided", () => {
  it("should reject when provided with a non-existent image and tag", async () => {
    await expect(() =>
      scan({
        path: "not-here:latest",
      }),
    ).rejects.toEqual(Error("authentication required"));
  });
});

describe("OCI images without platform tags", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "snykgoof/oci-goof:ociNoPlatformTag",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should correctly scan an OCI image without platform information in the tag", async () => {
    const image = "snykgoof/oci-goof:ociNoPlatformTag";

    const pluginResult = await scan({
      path: image,
      username: process.env.DOCKER_HUB_USERNAME,
      password: process.env.DOCKER_HUB_PASSWORD,
    });

    expect(pluginResult.scanResults).toBeDefined();
    expect(pluginResult.scanResults.length).toBeGreaterThan(0);
    expect(pluginResult.scanResults[0].facts).toBeDefined();
    expect(pluginResult.scanResults[0].facts.length).toBeGreaterThan(0);
  });
});
