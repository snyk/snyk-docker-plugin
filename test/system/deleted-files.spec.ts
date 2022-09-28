import * as path from "path";
import * as plugin from "../../lib";

describe("deleted files", () => {
  // arrange
  const getFixture = (fixturePath) =>
    path.join(__dirname, "../fixtures/docker-archives", fixturePath);

  /*
    The image in the example below was built with the following Dockerfile:

    FROM busybox
    COPY node /
    RUN rm /node
  */
  it("keyBinariesHashes should not exist in scan result", async () => {
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
    expect(
      result.facts.find((fact) => fact.type === "keyBinariesHashes"),
    ).toBeUndefined();
  });

  /*
    The image in the example below was built with the following Dockerfile:

    FROM alpine:latest
    RUN mkdir app
    COPY package.json /app/.
    COPY package-lock.json /app/.
    RUN rm /app/package-lock.json
    CMD sh
  */
  it("package-lock should be excluded from imageManifestFiles fact", async () => {
    // arrange
    const fixturePath = getFixture("docker-save/test-deleted.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    // act
    const pluginResult = await plugin.scan({
      path: imagePath,
      globsToFind: {
        include: ["**/package-lock.json", "**/package.json"],
        exclude: [],
      },
    });

    const result = pluginResult.scanResults[0];

    // assert
    expect(
      result.facts.find((fact) => fact.type === "imageManifestFiles").data
        .length,
    ).toEqual(1);
  });
});
