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
      location: "/uberjar.jar/lib/guava-30.1-jre.jar",
      digest: expect.any(String),
    };

    // TODO: deprecate --shaded-jars-depth and leave only --nested-jars-depth
    describe("--shaded-jars-depth", () => {
      describe("with all needed CLI flags (app-vulns and shaded-jars-depth)", () => {
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
            "shaded-jars-depth": "1",
          });

          fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
        });

        it("should return two results", async () => {
          expect(fingerprints).toHaveLength(2);
        });

        it("should return nested (second-level) jar in the result", async () => {
          expect(fingerprints).toContainEqual(
            expect.objectContaining(nestedJar),
          );
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

      describe("with default shaded-jars-depth", () => {
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
            "shaded-jars-depth": true,
          });

          fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
        });

        it("should return nested (second-level) jar in the result", async () => {
          expect(fingerprints).toContainEqual(
            expect.objectContaining(nestedJar),
          );
        });
      });

      describe("with missing CLI flags", () => {
        fixturePath = getFixture(
          "docker-archives/docker-save/java-uberjar.tar",
        );
        const imageNameAndTag = `docker-archive:${fixturePath}`;

        it("should not unpack jars if shaded-jars-depth flag is missing", async () => {
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

        it("should not unpack jars if shaded-jars-depth flag is set to 0", async () => {
          // Act
          pluginResult = await scan({
            path: imageNameAndTag,
            "app-vulns": true,
            "shaded-jars-depth": "0",
          });

          // Assert
          fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
          expect(fingerprints).toContainEqual(expect.objectContaining(fatJar));
          expect(fingerprints).not.toContainEqual(
            expect.objectContaining(nestedJar),
          );
        });

        it("should throw error if app-vulns flag is missing", async () => {
          // Act
          await expect(
            scan({
              path: imageNameAndTag,
              "shaded-jars-depth": "1",
            }),
          ).rejects.toThrow();
        });

      describe("with shaded-jars-depth=1", () => {
        beforeAll(async () => {
          // Arrange
          // todo: ensure fixture has dependencies
          fixturePath = getFixture("docker-archives/docker-save/pom-props.tar");
          const imageNameAndTag = `docker-archive:${fixturePath}`;

          // Act
          pluginResult = await scan({
            path: imageNameAndTag,
            "app-vulns": true,
            "shaded-jars-depth": "1",
          });

          fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
        });

        it("should return jar dependencies from pom.proprties files", async () => {
          expect(fingerprints[0]).toHaveProperty("dependencies");
          // expect(fingerprints[0].dependencies).toHaveLength(0);
        });
      });

      describe("with missing CLI flags", () => {
        fixturePath = getFixture(
          "docker-archives/docker-save/java-uberjar.tar",
        );
        const imageNameAndTag = `docker-archive:${fixturePath}`;

        it("should throw error if shaded-jars-depth is not a number", async () => {
          // Act
          await expect(
            scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "shaded-jars-depth": "NotANumber!",
            }),
          ).rejects.toThrow();
        });

        describe("multi-level jars", () => {
          let imageNameAndTag;
          beforeAll(async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/3-level-jar.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;
          });

          it("should return partial scan if shaded-jars-depth=1", async () => {
            const level2JarFingerprint = {
              location: "/level-3-jar.jar/level-2-jar.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "shaded-jars-depth": "1",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(1);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(level2JarFingerprint),
            );
          });

          it("should return full scan if shaded-jars-depth=2, because unpacking 2 levels will reveal the third", async () => {
            const deepestLevelJarFingerprint = {
              location:
                "/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "shaded-jars-depth": "2",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(1);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(deepestLevelJarFingerprint),
            );
          });

          it("should return full scan if shaded-jars-depth=4, because there are only 3 levels of jars", async () => {
            const deepestLevelJarFingerprint = {
              location:
                "/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "shaded-jars-depth": "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(1);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(deepestLevelJarFingerprint),
            );
          });

          it("should handle sibling uber jars", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/sibling-uberjars-deepest-first.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;
            const threeLevelFingerprint = {
              location:
                "/A-level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: expect.any(String),
            };
            const twoLevelFingerprint = {
              location: "/B-uber-jar.jar/guava-30.1-jre.jar",
              digest: expect.any(String),
            };
            const flatFingerprint = {
              location: "/C-j2objc-annotations-1.3.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "shaded-jars-depth": "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            // Assert
            expect(fingerprints).toHaveLength(3);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(threeLevelFingerprint),
            );
            expect(fingerprints).toContainEqual(
              expect.objectContaining(twoLevelFingerprint),
            );
            expect(fingerprints).toContainEqual(
              expect.objectContaining(flatFingerprint),
            );
          });

          // TODO CAP-447
          it.skip("should return correct levels unpacked for sibling jars, where the last is the deepest", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/sibling-uberjars-shallowest-first.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;
          });

          // TODO CAP-447
          it.skip("should return correct levels unpacked for sibling jars, where the first is the deepest", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/sibling-uberjars-deepest-first.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "shaded-jars-depth": "2",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;
            // tslint:disable-next-line:no-console
            console.log("🚀 ~ fingerprints", fingerprints);
          });

          it("should return correct result for top level jar that container 2 uberjars within it", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/top-level.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;

            const firstSibling = {
              digest: expect.any(String),
              location:
                "/top-level.jar/A-level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
            };
            const secondSibling = {
              digest: expect.any(String),
              location:
                "/top-level.jar/A-level-3-jar.jar/B-uber-jar.jar/guava-30.1-jre.jar",
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "shaded-jars-depth": "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            // Assert
            expect(fingerprints).toHaveLength(2);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(firstSibling),
            );
            expect(fingerprints).toContainEqual(
              expect.objectContaining(secondSibling),
            );
          });
        });
      });
    });

    describe("--nested-jars-depth", () => {
      it("should take the value of nested-jars-depth over shaded-jars-depth", async () => {
        // Arrange
        fixturePath = getFixture("docker-archives/docker-save/3-level-jar.tar");
        const imageNameAndTag = `docker-archive:${fixturePath}`;
        const level2JarFingerprint = {
          location: "/level-3-jar.jar/level-2-jar.jar",
          digest: expect.any(String),
        };
        const deepestLevelJarFingerprint = {
          location:
            "/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
          digest: expect.any(String),
        };

        // Act
        pluginResult = await scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "nested-jars-depth": "1",
          "shaded-jars-depth": "2",
        });

        fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;

        expect(fingerprints).toHaveLength(1);
        expect(fingerprints).toContainEqual(
          expect.objectContaining(level2JarFingerprint),
        );
        expect(fingerprints).not.toContainEqual(
          expect.objectContaining(deepestLevelJarFingerprint),
        );
      });

      describe("with all needed CLI flags (app-vulns and shaded-jars-depth)", () => {
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
            "shaded-jars-depth": "1",
          });

          fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
        });

        it("should return two results", async () => {
          expect(fingerprints).toHaveLength(2);
        });

        it("should return nested (second-level) jar in the result", async () => {
          expect(fingerprints).toContainEqual(
            expect.objectContaining(nestedJar),
          );
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

      describe("with default nested-jars-depth", () => {
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
            "nested-jars-depth": true,
          });

          fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
        });

        it("should return nested (second-level) jar in the result", async () => {
          expect(fingerprints).toContainEqual(
            expect.objectContaining(nestedJar),
          );
        });
      });

      describe("with missing CLI flags", () => {
        fixturePath = getFixture(
          "docker-archives/docker-save/java-uberjar.tar",
        );
        const imageNameAndTag = `docker-archive:${fixturePath}`;

        it("should not unpack jars if nested-jars-depth flag is missing", async () => {
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

        it("should not unpack jars if nested-jars-depth flag is set to 0", async () => {
          // Act
          pluginResult = await scan({
            path: imageNameAndTag,
            "app-vulns": true,
            "nested-jars-depth": "0",
          });

          // Assert
          fingerprints = pluginResult.scanResults[1].facts[0].data.fingerprints;
          expect(fingerprints).toContainEqual(expect.objectContaining(fatJar));
          expect(fingerprints).not.toContainEqual(
            expect.objectContaining(nestedJar),
          );
        });

        it("should throw error if app-vulns flag is missing", async () => {
          // Act
          await expect(
            scan({
              path: imageNameAndTag,
              "nested-jars-depth": "1",
            }),
          ).rejects.toThrow();
        });

        it("should throw error if nested-jars-depth is not a number", async () => {
          // Act
          await expect(
            scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "nested-jars-depth": "NotANumber!",
            }),
          ).rejects.toThrow();
        });

        describe("multi-level jars", () => {
          let imageNameAndTag;
          beforeAll(async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/3-level-jar.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;
          });

          it("should return partial scan if nested-jars-depth=1", async () => {
            const level2JarFingerprint = {
              location: "/level-3-jar.jar/level-2-jar.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "nested-jars-depth": "1",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(1);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(level2JarFingerprint),
            );
          });

          it("should return full scan if nested-jars-depth=2, because unpacking 2 levels will reveal the third", async () => {
            const deepestLevelJarFingerprint = {
              location:
                "/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "nested-jars-depth": "2",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(1);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(deepestLevelJarFingerprint),
            );
          });

          it("should return full scan if nested-jars-depth=4, because there are only 3 levels of jars", async () => {
            const deepestLevelJarFingerprint = {
              location:
                "/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "nested-jars-depth": "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(1);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(deepestLevelJarFingerprint),
            );
          });

          it("should handle sibling uber jars", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/sibling-uberjars-deepest-first.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;
            const threeLevelFingerprint = {
              location:
                "/A-level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: expect.any(String),
            };
            const twoLevelFingerprint = {
              location: "/B-uber-jar.jar/guava-30.1-jre.jar",
              digest: expect.any(String),
            };
            const flatFingerprint = {
              location: "/C-j2objc-annotations-1.3.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "nested-jars-depth": "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            // Assert
            expect(fingerprints).toHaveLength(3);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(threeLevelFingerprint),
            );
            expect(fingerprints).toContainEqual(
              expect.objectContaining(twoLevelFingerprint),
            );
            expect(fingerprints).toContainEqual(
              expect.objectContaining(flatFingerprint),
            );
          });

          // TODO CAP-447
          it.skip("should return correct levels unpacked for sibling jars, where the last is the deepest", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/sibling-uberjars-shallowest-first.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;
          });

          // TODO CAP-447
          it.skip("should return correct levels unpacked for sibling jars, where the first is the deepest", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/sibling-uberjars-deepest-first.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "nested-jars-depth": "2",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;
            // tslint:disable-next-line:no-console
            console.log("🚀 ~ fingerprints", fingerprints);
          });

          it("should return correct result for top level jar that container 2 uberjars within it", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/top-level.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;

            const firstSibling = {
              digest: expect.any(String),
              location:
                "/top-level.jar/A-level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
            };
            const secondSibling = {
              digest: expect.any(String),
              location:
                "/top-level.jar/A-level-3-jar.jar/B-uber-jar.jar/guava-30.1-jre.jar",
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              "nested-jars-depth": "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            // Assert
            expect(fingerprints).toHaveLength(2);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(firstSibling),
            );
            expect(fingerprints).toContainEqual(
              expect.objectContaining(secondSibling),
            );
          });
        });
      });
    });
  });
});
