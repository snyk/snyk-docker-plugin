import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("key binaries hashes scanning", () => {
  it("should correctly scan node key binaries hashes", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/nodes-fake-multi.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly scan java key binaries hashes", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/openjdk.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
