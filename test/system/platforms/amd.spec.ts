import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("AMD platform tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "redis@sha256:fed4c3c120450b140aaff9b125306cc58aba99876399b081a6ba054c0328a189",
    ]).catch();
  });

  it("should correctly scan an AMD image and return platform: amd64", async () => {
    const image =
      "redis@sha256:fed4c3c120450b140aaff9b125306cc58aba99876399b081a6ba054c0328a189";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly scan an AMD image when the user provides --platform=amd64 and return platform: amd64", async () => {
    const image =
      "redis@sha256:fed4c3c120450b140aaff9b125306cc58aba99876399b081a6ba054c0328a189";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
