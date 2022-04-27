import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("php application scans", () => {
  it("should correctly return applications as multiple scan results", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/php.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
    expect(pluginResult.scanResults).toHaveLength(2);
  });

  it("should not return PHP manifest files", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/php.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
      globsToFind: {
        include: [
          "**/composer.json",
          "**/composer.lock",
          "**/requirements.txt",
        ],
        exclude: [],
      },
    });

    expect(pluginResult).toMatchSnapshot();
    expect(pluginResult.scanResults).toHaveLength(2);
    expect(pluginResult.scanResults[0].facts).toHaveLength(6);
    const factTypes = pluginResult.scanResults[0].facts.map(
      (fact) => fact.type,
    );
    expect(factTypes).not.toContain("imageManifestFiles");
  });

  it("should handle --app-vulns with string and boolean value", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/php.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResultAppVulnsFalseString = await scan({
      path: imageNameAndTag,
      "app-vulns": "false",
    });

    const pluginResultAppVulnsTrueString = await scan({
      path: imageNameAndTag,
      "app-vulns": "true",
    });

    const pluginResultAppVulnsFalseBoolean = await scan({
      path: imageNameAndTag,
      "app-vulns": false,
    });

    const pluginResultAppVulnsTrueBoolean = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResultAppVulnsFalseString.scanResults).toHaveLength(1);
    expect(pluginResultAppVulnsFalseBoolean.scanResults).toHaveLength(1);

    expect(pluginResultAppVulnsTrueString.scanResults).toHaveLength(2);
    expect(pluginResultAppVulnsTrueBoolean.scanResults).toHaveLength(2);
  });
});
