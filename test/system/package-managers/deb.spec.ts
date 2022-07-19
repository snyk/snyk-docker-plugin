import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("deb package manager tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "debian@sha256:89ff9e144a438f6bdf89fba6a1fdcb614b6d03bc14433bbb937088ca7c7a7b6d",
    ]).catch();
  });

  it("should correctly analyze a deb image", async () => {
    const image =
      "debian@sha256:89ff9e144a438f6bdf89fba6a1fdcb614b6d03bc14433bbb937088ca7c7a7b6d";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
