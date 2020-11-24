import { scan } from "../../lib";
import { getFixture } from "../util";

describe("scanning a container image with 2 applications", () => {
  it("should return expected result", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});

describe("jar binaries scanning", () => {
  it("should return expected result", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/java-windows.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
