import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("docker archive scanning", () => {
  it("should correctly scan a docker archive", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/nginx.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});

describe("handles bad input being provided", () => {
  it("should reject when provided with a non-existent docker-archive", async () => {
    await expect(() =>
      scan({
        path: "docker-archive:not-here.tar",
      }),
    ).rejects.toEqual(
      Error("The provided archive path does not exist on the filesystem"),
    );
  });
});
