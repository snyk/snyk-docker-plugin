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

  it("should handle --exclude-app-vulns with string and boolean value", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/php.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResultExcludeAppVulnsFalseString = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": "false",
    });

    const pluginResultExcludeAppVulnsTrueString = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": "true",
    });

    const pluginResultExcludeAppVulnsFalseBoolean = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": false,
    });

    const pluginResultExcludeAppVulnsTrueBoolean = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": true,
    });

    expect(pluginResultExcludeAppVulnsFalseString.scanResults).toHaveLength(2);
    expect(pluginResultExcludeAppVulnsFalseBoolean.scanResults).toHaveLength(2);

    expect(pluginResultExcludeAppVulnsTrueString.scanResults).toHaveLength(1);
    expect(pluginResultExcludeAppVulnsTrueBoolean.scanResults).toHaveLength(1);
  });
});
