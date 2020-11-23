import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("jar binaries scanning", () => {
  it("should return expected result", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/java.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
