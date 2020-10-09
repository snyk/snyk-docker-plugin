import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("PPC64 platform tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "ppc64le/php:8.0.0rc1-fpm-alpine3.12",
    ]).catch();
  });

  it("should correctly scan a PPC image and return platform: ppc64le", async () => {
    const image = "ppc64le/php:8.0.0rc1-fpm-alpine3.12";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly scan a PPC image when the user provides --platform=ppc64le and return platform: ppc64le", async () => {
    const image = "ppc64le/php:8.0.0rc1-fpm-alpine3.12";
    const pluginResult = await scan({
      path: image,
      platform: "linux/ppc64le",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
