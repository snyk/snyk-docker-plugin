import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("debian tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "debian@sha256:e7157902df9c7549eea5eb7b896cdca02d917e2ba0e339cd4a5087e2b53eb1d7",
    ]).catch();
  });

  it("should correctly analyze a debian image by sha256", async () => {
    const image =
      "debian@sha256:e7157902df9c7549eea5eb7b896cdca02d917e2ba0e339cd4a5087e2b53eb1d7";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
