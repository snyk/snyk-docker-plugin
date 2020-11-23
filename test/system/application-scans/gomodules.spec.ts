import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("gomodules binaries scanning", () => {
  it("should return expected result", async () => {
    // Arrange
    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    // Act
    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    // Assert
    expect(pluginResult).toMatchSnapshot();
  });
});
