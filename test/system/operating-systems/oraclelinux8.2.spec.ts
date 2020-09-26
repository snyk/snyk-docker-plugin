import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("oracle linux tests", () => {
  afterAll(async () => {
    await execute("docker", ["image", "rm", "oraclelinux:8.2"]).catch();
    await execute("docker", [
      "image",
      "rm",
      "oraclelinux@sha256:652409ec0fd4e79b07ecf82e35ebf50277be69f6b8e873129a55a0bdedf827d0",
    ]).catch();
  });

  it("should correctly analyze an oracle linux image by tag", async () => {
    const image = "oraclelinux:8.2";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze an oracle linux image by sha256", async () => {
    const image =
      "oraclelinux@sha256:652409ec0fd4e79b07ecf82e35ebf50277be69f6b8e873129a55a0bdedf827d0";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
