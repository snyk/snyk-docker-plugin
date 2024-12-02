import { scan } from "../../../../lib";
import { getFixture } from "../../../util";

describe("pip application scan", () => {
  it("should correctly return applications as multiple scan results", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/pip.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
    expect(pluginResult.scanResults).toHaveLength(2);
  });

  it("should correctly return applications as multiple scan results with dist-packages", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/pip-dist-packages.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
    expect(pluginResult.scanResults).toHaveLength(2);
  });

  it("should handle --exclude-app-vulns with string and boolean value", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/pip.tar");
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

  it("should handle --collect-application-files", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/pip-flask.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const resultWithoutApplicationFilesFlag = await scan({
      path: imageNameAndTag,
    });
    const resultWithApplicationFilesFlagSetToTrue = await scan({
      path: imageNameAndTag,
      "collect-application-files": "true",
    });

    expect(resultWithoutApplicationFilesFlag.scanResults).toHaveLength(2);
    expect(resultWithApplicationFilesFlagSetToTrue.scanResults).toHaveLength(3);

    const appFiles =
      resultWithApplicationFilesFlagSetToTrue.scanResults[2].facts.find(
        (fact) => fact.type === "applicationFiles",
      )!.data;
    expect(appFiles[0].language).toStrictEqual("python");
    expect(appFiles[0].fileHierarchy).toStrictEqual([
      { path: "/app/server.py" },
    ]);
  });
});
