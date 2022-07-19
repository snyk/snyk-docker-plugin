import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("apk package manager tests", () => {
  afterAll(async () => {
    await execute("docker", ["image", "rm", "alpine:3.12.0"]).catch();
  });

  it("should correctly analyze an apk image", async () => {
    const image = "alpine:3.12.0";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
