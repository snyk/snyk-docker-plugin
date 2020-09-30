import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("scratch tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "snyk/runtime-fixtures:scratch",
    ]).catch();
  });

  it("should correctly analyze an scratch image by sha256", async () => {
    const image = "snyk/runtime-fixtures:scratch";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
