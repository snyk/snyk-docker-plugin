import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("node application scans", () => {
  it("should correctly return applications as multiple scan results", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
    expect(pluginResult.scanResults).toHaveLength(3);
  });

  it("should handle --app-vulns with string and boolean value", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
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

    expect(pluginResultAppVulnsTrueString.scanResults).toHaveLength(3);
    expect(pluginResultAppVulnsTrueBoolean.scanResults).toHaveLength(3);
  });
});
