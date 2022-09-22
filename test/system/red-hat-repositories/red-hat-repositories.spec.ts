import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("key binaries hashes scanning", () => {
  it("should correctly scan rpm repositories", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/nginx-with-buildinfo.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
