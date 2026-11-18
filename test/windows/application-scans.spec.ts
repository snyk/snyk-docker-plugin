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
      "docker-archives/docker-save/go-windows.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});

describe("go binaries scanning with esbuild npm path that previously failed extension matching on Windows", () => {
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
  });
});

describe("ruby Gemfile.lock scanning", () => {
  it("should return one rubygems result from gemfile.tar", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    const rubyResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "rubygems",
    );
    expect(rubyResults).toHaveLength(1);
    // Extractor keys use the host separator (\Gemfile.lock on Windows).
    expect(rubyResults[0].identity.targetFile).toMatch(/[/\\]Gemfile\.lock$/);
  });
});
