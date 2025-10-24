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

describe("go binaries scanning", () => {
  it("should return expected result", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/go-binaries.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();

    expect(pluginResult.scanResults.length).toEqual(4);

    // esbuild go binary should be found in the scan results
    const esbuildResultFound = pluginResult.scanResults.find(
      (r) => r.identity.targetFile && r.identity.targetFile.includes("esbuild"),
    );

    expect(esbuildResultFound).toBeTruthy();
  });
});
