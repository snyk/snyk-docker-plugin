import * as elf from "elfy";

import { PluginResponse, scan } from "../../../lib";
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

  it("return plugin result when Go binary cannot be parsed do not break layer iterator", async () => {
    const elfParseMock = jest.spyOn(elf, "parse").mockImplementation(() => {
      throw new Error("Cannot read property 'type' of undefined");
    });

    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });
    expect(pluginResult).toMatchSnapshot();
    elfParseMock.mockRestore();
  });
});
