import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";
import { getFixture } from "../../util";

describe("ARM platform tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "arm64v8/nginx:1.19.2-alpine",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should correctly scan an ARM image", async () => {
    const image = "arm64v8/nginx:1.19.2-alpine";
    const pluginResult = await scan({
      path: image,
      platform: "linux/arm64",
    });

    expect(pluginResult).toMatchSnapshot();
  });
  test("should correctly scan an arm64 image when platform flag is missing", async () => {
    const fixturePath = getFixture("docker-archives/alpine-arm64.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;
    try {
      const result = await scan({
        path: imageNameAndTag,
      });
      expect(result).toBeDefined();
    } catch (error) {
      expect(error.message).not.toBe("Invalid OCI Archive");
    }
  });

  it.todo(
    "should correctly scan an ARM image when the user provides --platform=arm and return platform: arm",
  );
});
