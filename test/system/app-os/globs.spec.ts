import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("find globs tests", () => {
  afterAll(async () => {
    await execute("docker", ["image", "rm", "debian:10"]).catch();
  });

  it("should correctly return manifest files when detected by globs", async () => {
    const image = "debian:10";
    const pluginResult = await scan({
      path: image,
      globsToFind: {
        include: ["**/os-release"],
        exclude: [],
      },
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
