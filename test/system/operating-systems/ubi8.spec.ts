import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("redhat ubi8 tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "registry.access.redhat.com/ubi8/ubi:8.2-347",
    ]).catch();
  });

  it("should correctly analyze an ubi8 image by tag", async () => {
    const image = "registry.access.redhat.com/ubi8/ubi:8.2-347";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
