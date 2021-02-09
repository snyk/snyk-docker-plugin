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

  it("throws an error when a Go binary cannot be parsed", async () => {
    const elfParseMock = jest.spyOn(elf, "parse").mockImplementation(() => {
      throw new Error("Cannot read property 'type' of undefined");
    });

    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    await expect(() =>
      scan({
        path: imageNameAndTag,
        "app-vulns": true,
      }),
    ).rejects.toThrow("Error reading tar archive");

    elfParseMock.mockRestore();
  });
});
