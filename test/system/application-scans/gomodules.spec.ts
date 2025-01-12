import * as elf from "elfy";

import { extractContent, scan } from "../../../lib";
import { getGoModulesContentAction } from "../../../lib/go-parser";
import { getFixture } from "../../util";

describe("gomodules binaries scanning", () => {
  afterAll(() => {
    jest.resetAllMocks();
  });

  it("should return expected result", async () => {
    // Arrange
    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    // Act
    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    // Assert
    expect(pluginResult).toMatchSnapshot();
  });

  it("should extract image content successfully", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.17.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;
    const result = await extractContent([getGoModulesContentAction], {
      path: imageNameAndTag,
    });
    const testgoBinary = result.extractedLayers["/testgo"];
    expect(testgoBinary).toBeTruthy();
    expect("gomodules" in testgoBinary).toBeTruthy();
  });

  it("return plugin result when Go binary cannot be parsed do not break layer iterator", async () => {
    const elfParseMock = jest.spyOn(elf, "parse").mockImplementation(() => {
      throw new Error("Cannot read property 'type' of undefined");
    });

    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });
    expect(pluginResult).toMatchSnapshot();
    elfParseMock.mockRestore();
  });
});

describe("parse go modules from various versions of compiled binaries", () => {
  it("go 1.17", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.17.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("go 1.18", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.18.3.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("go 1.19", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.19rc1.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
