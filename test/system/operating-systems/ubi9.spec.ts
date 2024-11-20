import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("redhat ubi9 tests", () => {
  afterAll(async () => {
    await execute("docker", ["image", "rm", "redhat/ubi9-micro:9.3"]).catch(
      () => {
        console.error(`tests teardown failed to remove docker image`);
      },
    );
  });

  it("should correctly analyze an ubi9 image by tag", async () => {
    const image = "redhat/ubi9-micro:9.3";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
