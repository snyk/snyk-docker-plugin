import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("deb package manager tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "debian:stable-20200908-slim",
    ]).catch();
  });

  it("should correctly analyze a deb image", async () => {
    const image = "debian:stable-20200908-slim";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
