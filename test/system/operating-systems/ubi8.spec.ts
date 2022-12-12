import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("redhat ubi8 tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "registry.access.redhat.com/ubi8/ubi:8.2-347",
    ]).catch();
  });

  it("should correctly analyze an ubi8 image by tag", async () => {
    const image = "registry.access.redhat.com/ubi8/ubi:8.2-347";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});

describe("redhat modules tests", () => {
  it("should correctly analyze redhat module", async () => {
    const image =
      "registry.access.redhat.com/ubi8/nodejs-10@sha256:d344ac95abeeb0d5e2b2897caca0c806fae925b12f82242fc34e0a9d2eb785ca";
    const pluginResult = await scan({ path: image, platform: "linux/amd64" });

    expect(pluginResult).toMatchSnapshot();
  });
});
