import { scan } from "../../../../lib/index";
import { execute } from "../../../../lib/sub-process";

describe("apk package manager tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "alpine:3.12.0",
      "chainguard/bash@sha256:642933df66209814502599053ca3dfa97cccf847badc4219d2b1fd6565f6559a",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should correctly analyze an apk image", async () => {
    const image = "alpine:3.12.0";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze an apk image with newer wolfi/chainguard database location at /usr/lib/apk/", async () => {
    const image =
      "chainguard/bash@sha256:642933df66209814502599053ca3dfa97cccf847badc4219d2b1fd6565f6559a";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
