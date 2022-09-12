import * as path from "path";
import * as plugin from "../../lib";

describe("scan result should not contain any deleted file", () => {
  const getFixture = (fixturePath) =>
    path.join(__dirname, "../fixtures/docker-archives", fixturePath);

  it("scan result don't bring deleted facts", async () => {
    // arrange
    const fixturePath = getFixture("skopeo-copy/node-removed.tar");
    const imagePath = `oci-archive:${fixturePath}`;

    // act
    const pluginResult = await plugin.scan({
      path: imagePath,
    });

    const result = pluginResult.scanResults[0];

    // assert
    expect(result).toHaveProperty("facts");
    // expect(result["keyBinariesHashes"]).toBeUndefined();
  });

  it("scan result don't bring deleted lock file", async () => {
    // arrange
    const fixturePath = getFixture("docker-save/test-deleted.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    // act
    const pluginResult = await plugin.scan({
      path: imagePath,
    });

    const result = pluginResult.scanResults[0];

    // assert
    expect(result).toHaveProperty("facts");
    // expect(result["keyBinariesHashes"]).toBeUndefined();
  });
});
