import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("rpm package manager tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "amazonlinux:2.0.20200722.0",
      "amazonlinux:2022.0.20220504.1",
    ]).catch();
  });

  it("should correctly analyze an rpm image", async () => {
    const image = "amazonlinux:2.0.20200722.0";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze an rpm image with sqlite DB", async () => {
    const image = "amazonlinux:2022.0.20220504.1";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
