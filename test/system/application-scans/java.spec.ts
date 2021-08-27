import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("jar binaries scanning", () => {
  it("should return expected result", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/java.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  describe("uber jars", () => {
    let fixturePath;
    let pluginResult;
    let fingerprints;

    const fatJar = {
      location: "/uberjar.jar",
      digest: expect.any(String),
    };
    const nestedJar = {
      location: "lib/guava-30.1-jre.jar",
      digest: expect.any(String),
    };

    describe("with all needed CLI flags (app-vulns and shaded-jars)", () => {
      beforeAll(async () => {
        // Arrange
        fixturePath = getFixture(
          "docker-archives/docker-save/java-uberjar.tar",
        );
        const imageNameAndTag = `docker-archive:${fixturePath}`;

        // Act
        pluginResult = await scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "shaded-jars": true,
        });

        fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
      });

      it("should return two results", async () => {
        expect(fingerprints).toHaveLength(2);
      });

      it("should return nested (second-level) jar in the result", async () => {
        expect(fingerprints).toContainEqual(expect.objectContaining(nestedJar));
      });

      it("should not return a first-level jar that have nested jars in it (uber jar)", async () => {
        expect(fingerprints).not.toContainEqual(
          expect.objectContaining(fatJar),
        );
      });

      it("should return first-level jars that have no nested jars in it", async () => {
        expect(fingerprints).toContainEqual(
          expect.objectContaining({
            location: "/j2objc-annotations-1.3.jar",
            digest: expect.any(String),
          }),
        );
      });
    });

    describe("with missing CLI flags", () => {
      fixturePath = getFixture("docker-archives/docker-save/java-uberjar.tar");
      const imageNameAndTag = `docker-archive:${fixturePath}`;

      it("should not unpack jars if shaded-jars flag is missing", async () => {
        // Act
        pluginResult = await scan({
          path: imageNameAndTag,
          "app-vulns": true,
        });

        // Assert
        fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
        expect(fingerprints).toContainEqual(expect.objectContaining(fatJar));
        expect(fingerprints).not.toContainEqual(
          expect.objectContaining(nestedJar),
        );
      });

      it("should throw error app-vulns flag is missing", async () => {
        // Act
        await expect(
          scan({
            path: imageNameAndTag,
            "shaded-jars": true,
          }),
        ).rejects.toThrow();
      });
    });
  });
});
