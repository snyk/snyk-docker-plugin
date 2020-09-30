import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("ARM platform tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "arm64v8/nginx:1.19.2-alpine",
    ]).catch();
  });

  it("should correctly scan an ARM image", async () => {
    const image = "arm64v8/nginx:1.19.2-alpine";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it.todo(
    "should correctly scan an ARM image when the user provides --platform=arm and return platform: arm",
  );
});
