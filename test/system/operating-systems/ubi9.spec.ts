import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("redhat ubi9 tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "registry.access.redhat.com/ubi9-micro",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should correctly analyze an ubi9 image by tag", async () => {
    const image = "registry.access.redhat.com/ubi9-micro";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
