import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("centos tests", () => {
  afterAll(async () => {
    await execute("docker", ["image", "rm", "centos:7.8.2003"]).catch();
    await execute("docker", [
      "image",
      "rm",
      "centos@sha256:50b9a3bc27378889210f88d6d0695938e45a912aa99b3fdacfb9a0fef511f15a",
    ]).catch();
  });

  it("should correctly analyze a centos image by tag", async () => {
    const image = "centos:7.8.2003";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a centos image by sha256", async () => {
    const image =
      "centos@sha256:50b9a3bc27378889210f88d6d0695938e45a912aa99b3fdacfb9a0fef511f15a";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
