import { join as pathJoin } from "path";
import { scan } from "../../lib/index";

function getFixture(fixturePath: string): string {
  return pathJoin(__dirname, "../fixtures/docker-archives", fixturePath);
}

describe("scanning a container image with 2 applications", () => {
  it("should return expected result", async () => {
    const fixturePath = getFixture("skopeo-copy/rpm-npm-yarn.tar");
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
    const fixturePath = getFixture("docker-save/java-windows.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
