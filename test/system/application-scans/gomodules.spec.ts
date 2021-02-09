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

  it("throws an uncaught exception when a binary cannot be parsed", async () => {
    const elfParseMock = jest.spyOn(elf, "parse").mockImplementation(() => {
      throw new Error("Cannot read property 'type' of undefined");
    });

    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    try {
      const pluginResult = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
      });
      expect(pluginResult).toEqual<PluginResponse>({
        scanResults: expect.any(Array),
      });
    } catch (error) {
      // This won't be executed!
      expect(error).toBeDefined();
    }

    elfParseMock.mockRestore();
  });
});
