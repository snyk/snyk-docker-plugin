import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("suse linux enterprise server tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "registry.suse.com/suse/sle15:15.2.8.2.751",
    ]).catch();
  });

  it("should correctly analyze an sles image by tag", async () => {
    const image = "registry.suse.com/suse/sle15:15.2.8.2.751";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
