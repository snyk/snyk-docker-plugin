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

describe("Deleted Folders", () => {
  const getFixture = (fixturePath) =>
    path.join(__dirname, "../fixtures/docker-archives", fixturePath);

  /*
    The image in the example below was built with the following Dockerfile:

    FROM alpine:latest
    WORKDIR /app
    RUN mkdir jar_folder && wget https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar && mv commons-collections-3.2.1.jar jar_folder
    RUN rm -rf /app/jar_folder
    RUN echo "hello"
  */
  it("commons-collections should be excluded from dependency tree", async () => {
    const fixturePath = getFixture("docker-save/deleted-folder.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imagePath,
    });

    // There should only be the distro scan result. The maven scan result should not exist.
    expect(pluginResult.scanResults.length).toEqual(1);
  });

  /*
    The image in the example below was built with the following Dockerfile:

    FROM alpine:latest
    WORKDIR /app
    RUN mkdir jar_folder &&  wget https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar && wget https://repo1.maven.org/maven2/com/google/guava/guava/30.1-jre/guava-30.1-jre.jar && mv commons-collections-3.2.1.jar guava-30.1-jre.jar jar_folder
    RUN rm -rf /app/jar_folder
    RUN echo "hello"
   */
  it("Both commons-collections and guava should be excluded from dependency tree", async () => {
    const fixturePath = getFixture("docker-save/deleted-multi.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imagePath,
    });

    // There should only be the distro scan result. The maven scan result should not exist.
    expect(pluginResult.scanResults.length).toEqual(1);
  });

  /*
    The image in the example below was built with the following Dockerfile:

    FROM alpine:latest
    WORKDIR /app
    RUN mkdir jar_folder &&  wget https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar && wget https://repo1.maven.org/maven2/com/google/guava/guava/30.1-jre/guava-30.1-jre.jar && mv commons-collections-3.2.1.jar guava-30.1-jre.jar jar_folder
    RUN rm -rf /app/jar_folder
    RUN mkdir jar_folder && wget https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar && mv commons-lang3-3.12.0.jar jar_folder
    RUN echo "hello"

   */
  it("commons-lang3 should still exist even though the parent folder was deleted and recreated", async () => {
    const fixturePath = getFixture("docker-save/deleted-recreated.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imagePath,
    });

    // There should only be the distro scan result. The maven scan result should not exist.
    expect(pluginResult.scanResults.length).toEqual(2);

    const result = pluginResult.scanResults[1];
    expect(result.facts["0"].data.fingerprints["0"].artifactId).toEqual(
      "commons-lang3",
    );
  });
});
