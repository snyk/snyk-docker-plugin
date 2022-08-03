import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("alpine tests", () => {
  afterAll(async () => {
    await execute("docker", ["image", "rm", "alpine:3.7.3"]).catch();
    await execute("docker", [
      "image",
      "rm",
      "alpine@sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b",
    ]).catch();
  });

  it("should correctly analyze an alpine image by tag", async () => {
    const image = "alpine:3.7.3";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze an alpine image by sha256", async () => {
    const image =
      "alpine@sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
