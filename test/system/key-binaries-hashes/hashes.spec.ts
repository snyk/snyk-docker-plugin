import { join as pathJoin } from "path";
import { scan } from "../../../lib/index";

function getFixture(fixturePath: string): string {
  return pathJoin(__dirname, "../../fixtures/docker-archives", fixturePath);
}

describe("key binaries hashes scanning", () => {
  it("should correctly scan node key binaries hashes", async () => {
    const fixturePath = getFixture("skopeo-copy/nodes-fake-multi.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly scan java key binaries hashes", async () => {
    const fixturePath = getFixture("docker-save/openjdk.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
