import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("chisel package manager tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "snykgoof/dockerhub-goof:ubuntu-chisel-24.04",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should correctly analyze a chiseled Ubuntu image", async () => {
    const image = "snykgoof/dockerhub-goof:ubuntu-chisel-24.04";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
