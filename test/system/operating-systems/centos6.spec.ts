import { scan } from "../../../lib";
import { Docker } from "../../../lib/docker";
import { execute } from "../../../lib/sub-process";

describe("CentOS 6 tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "dokken/centos-6@sha256:494b9b280814f1e661597b48e229156e4dccb60dce198d9210f7572ff22626d2",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("can scan a centos6-based image", async () => {
    const imagePath =
      "dokken/centos-6@sha256:494b9b280814f1e661597b48e229156e4dccb60dce198d9210f7572ff22626d2";

    const pluginResponse = await scan({
      path: imagePath,
      platform: "linux/amd64",
      "exclude-app-vulns": true,
    });
    expect(pluginResponse).toMatchSnapshot();
  });

  it("can scan a centos6-based image with app vulns", async () => {
    const imagePath =
      "dokken/centos-6@sha256:494b9b280814f1e661597b48e229156e4dccb60dce198d9210f7572ff22626d2";

    const pluginResponse = await scan({
      path: imagePath,
      platform: "linux/amd64",
    });
    expect(pluginResponse).toMatchSnapshot();
  });
});
