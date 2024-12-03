import { scan } from "../../../../lib";
import { filterAppFiles } from "../../../../lib/analyzer/applications/python/common";
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
    expect(appFiles[0].fileHierarchy).toStrictEqual([{ path: "server.py" }]);
  });
});

describe("python application files filtering", () => {
  it("should correctly filter python application files", async () => {
    const pythonProjectFiles = [
      "/app/index.py",
      "/app/src/app.py",
      "/app/src/utils/helpers.py",
      "/app/src/components/header.py",
      "/app/src/components/footer.py",
      "/app/src/services/api.py",
      "/app/src/models/user.py",
      "/app/src/config/config.py",
      "/requirements.txt",
      "/Dockerfile",
      "/README.md",
    ];
    const [appFilesRootDir, appFiles] = filterAppFiles(pythonProjectFiles);

    expect(appFilesRootDir).toBe("/app");
    expect(appFiles.length).toBe(8);
    expect(appFiles).toEqual([
      { path: "index.py" },
      { path: "src/app.py" },
      { path: "src/utils/helpers.py" },
      { path: "src/components/header.py" },
      { path: "src/components/footer.py" },
      { path: "src/services/api.py" },
      { path: "src/models/user.py" },
      { path: "src/config/config.py" },
    ]);
  });
});
