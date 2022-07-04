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
      dependencies: expect.any(Array),
    };
    const nestedJar = {
      location: "/uberjar.jar/lib/guava-30.1-jre.jar",
      digest: null,
      artifactId: "guava",
      groupId: "com.google.guava",
      version: "30.1-jre",
      dependencies: expect.any(Array),
    };

    // TODO: deprecate --shaded-jars-depth and leave only --nested-jars-depth
    describe.each(["shaded-jars-depth", "nested-jars-depth"])(
      "--%s",
      (flagName) => {
        describe(`with all needed CLI flags (app-vulns and ${flagName})`, () => {
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
              [flagName]: "1",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;
          });

          it("should return the Uber JAR and two nested JARs in the results", () => {
            expect(fingerprints).toHaveLength(3);
          });

          it("should return nested (second-level) jar in the result", () => {
            expect(fingerprints).toContainEqual(nestedJar);
          });

          it("should return a first-level jar that have nested jars in it (uber jar)", () => {
            expect(fingerprints).toContainEqual(fatJar);
          });

          it("should be a unique set of fingerprints", () => {
            const isUniqueList = (arr: any[]): boolean =>
              arr.length === new Set(arr).size;
            expect(isUniqueList(fingerprints)).toBeTruthy();
          });

          it("should return first-level jars that have no nested jars in it", () => {
            expect(fingerprints).toContainEqual({
              location: "/j2objc-annotations-1.3.jar",
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "j2objc-annotations",
              groupId: "com.google.j2objc",
              version: "1.3",
            });
          });
        });

        describe(`with default ${flagName}`, () => {
          // Arrange
          let imageNameAndTag;
          beforeAll(async () => {
            fixturePath = getFixture(
              "docker-archives/docker-save/java-uberjar.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;
          });

          it("should return nested (second-level) jar in the result", async () => {
            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              [flagName]: true,
            });

            // Assert
            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toContainEqual(nestedJar);
          });

          it(`should unpack 1 level of jars if ${flagName} flag is missing`, async () => {
            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toContainEqual(nestedJar);
          });
        });

        describe("with missing CLI flags", () => {
          fixturePath = getFixture(
            "docker-archives/docker-save/java-uberjar.tar",
          );
          const imageNameAndTag = `docker-archive:${fixturePath}`;

          it(`should not unpack jars if ${flagName} flag is set to 0`, async () => {
            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              [flagName]: "0",
            });

            // Assert
            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;
            expect(fingerprints).toContainEqual(fatJar);
            expect(fingerprints).not.toContainEqual(nestedJar);
          });

          it(`should throw if ${flagName} flag is set to -1`, async () => {
            // Act + Assert
            await expect(
              scan({
                path: imageNameAndTag,
                "app-vulns": true,
                [flagName]: "-1",
              }),
            ).rejects.toThrow();
          });

          it("should throw error if exclude-app-vulns flag is true", async () => {
            // Act
            await expect(
              scan({
                path: imageNameAndTag,
                "exclude-app-vulns": true,
                [flagName]: "1",
              }),
            ).rejects.toThrow();
          });

          it(`should throw error if ${flagName} is not a number`, async () => {
            // Act
            await expect(
              scan({
                path: imageNameAndTag,
                "app-vulns": true,
                [flagName]: "NotANumber!",
              }),
            ).rejects.toThrow();
          });
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

          it(`should return partial scan if ${flagName}=1`, async () => {
            const level2JarFingerprint = {
              location: "/level-3-jar.jar/level-2-jar.jar",
              digest: expect.any(String),
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              [flagName]: "1",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(2);
            expect(fingerprints).toContainEqual(
              expect.objectContaining(level2JarFingerprint),
            );
          });

          it(`should return full scan if ${flagName}=2, because unpacking 2 levels will reveal the third`, async () => {
            const deepestLevelJarFingerprint = {
              location:
                "/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "listenablefuture",
              groupId: "com.google.guava",
              version: "9999.0-empty-to-avoid-conflict-with-guava",
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              [flagName]: "2",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(3);
            expect(fingerprints).toContainEqual(deepestLevelJarFingerprint);
          });

          it(`should return full scan if ${flagName}=4, because specifying more levels than exist should not break things`, async () => {
            const deepestLevelJarFingerprint = {
              location:
                "/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "listenablefuture",
              groupId: "com.google.guava",
              version: "9999.0-empty-to-avoid-conflict-with-guava",
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              [flagName]: "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            expect(fingerprints).toHaveLength(3);
            expect(fingerprints).toContainEqual(deepestLevelJarFingerprint);
          });

          describe("WAR files", () => {
            let imageNameAndTag;
            beforeAll(async () => {
              // Arrange
              fixturePath = getFixture(
                "docker-archives/docker-save/war-with-3-level-jar.tar",
              );
              imageNameAndTag = `docker-archive:${fixturePath}`;
            });
            it(`should return partial scan if ${flagName}=2`, async () => {
              const level2JarFingerprint = {
                location:
                  "/workspace/app/mywar.war/WEB-INF/lib/level-3-jar.jar/level-2-jar.jar",
                digest: expect.any(String),
              };

              // Act
              pluginResult = await scan({
                path: imageNameAndTag,
                "app-vulns": true,
                [flagName]: "2",
              });

              fingerprints =
                pluginResult.scanResults[1].facts[0].data.fingerprints;

              expect(fingerprints).toHaveLength(5);
              expect(fingerprints).toContainEqual(
                expect.objectContaining(level2JarFingerprint),
              );
            });

            it(`should return full scan if ${flagName}=3, because unpacking 3 levels will reveal the third`, async () => {
              const deepestLevelJarFingerprint = {
                location:
                  "/workspace/app/mywar.war/WEB-INF/lib/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
                digest: null,
                dependencies: expect.any(Array),
                artifactId: "listenablefuture",
                groupId: "com.google.guava",
                version: "9999.0-empty-to-avoid-conflict-with-guava",
              };

              // Act
              pluginResult = await scan({
                path: imageNameAndTag,
                "app-vulns": true,
                [flagName]: "3",
              });

              fingerprints =
                pluginResult.scanResults[1].facts[0].data.fingerprints;

              expect(fingerprints).toHaveLength(6);
              expect(fingerprints).toContainEqual(deepestLevelJarFingerprint);
            });

            it(`should return full scan if ${flagName}=4, because specifying more levels than exist should not break things`, async () => {
              const deepestLevelJarFingerprint = {
                location:
                  "/workspace/app/mywar.war/WEB-INF/lib/level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
                digest: null,
                dependencies: expect.any(Array),
                artifactId: "listenablefuture",
                groupId: "com.google.guava",
                version: "9999.0-empty-to-avoid-conflict-with-guava",
              };

              // Act
              pluginResult = await scan({
                path: imageNameAndTag,
                "app-vulns": true,
                [flagName]: "4",
              });

              fingerprints =
                pluginResult.scanResults[1].facts[0].data.fingerprints;

              expect(fingerprints).toHaveLength(6);
              expect(fingerprints).toContainEqual(deepestLevelJarFingerprint);
            });
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
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "listenablefuture",
              groupId: "com.google.guava",
              version: "9999.0-empty-to-avoid-conflict-with-guava",
            };
            const twoLevelFingerprint = {
              location: "/B-uber-jar.jar/guava-30.1-jre.jar",
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "guava",
              groupId: "com.google.guava",
              version: "30.1-jre",
            };
            const flatFingerprint = {
              location: "/C-j2objc-annotations-1.3.jar",
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "j2objc-annotations",
              groupId: "com.google.j2objc",
              version: "1.3",
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              [flagName]: "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            // Assert
            expect(fingerprints).toHaveLength(6);
            expect(fingerprints).toContainEqual(threeLevelFingerprint);
            expect(fingerprints).toContainEqual(twoLevelFingerprint);
            expect(fingerprints).toContainEqual(flatFingerprint);
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
              [flagName]: "2",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;
            // tslint:disable-next-line:no-console
            console.log("🚀 ~ fingerprints", fingerprints);
          });

          it("should return correct result for top level jar that contains 2 uberjars within it", async () => {
            // Arrange
            fixturePath = getFixture(
              "docker-archives/docker-save/top-level.tar",
            );
            imageNameAndTag = `docker-archive:${fixturePath}`;

            const firstSibling = {
              location:
                "/top-level.jar/A-level-3-jar.jar/level-2-jar.jar/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "listenablefuture",
              groupId: "com.google.guava",
              version: "9999.0-empty-to-avoid-conflict-with-guava",
            };
            const secondSibling = {
              location: "/top-level.jar/B-uber-jar.jar/guava-30.1-jre.jar",
              digest: null,
              dependencies: expect.any(Array),
              artifactId: "guava",
              groupId: "com.google.guava",
              version: "30.1-jre",
            };

            // Act
            pluginResult = await scan({
              path: imageNameAndTag,
              "app-vulns": true,
              [flagName]: "4",
            });

            fingerprints =
              pluginResult.scanResults[1].facts[0].data.fingerprints;

            // Assert
            expect(fingerprints).toHaveLength(6);
            expect(fingerprints).toContainEqual(firstSibling);
            expect(fingerprints).toContainEqual(secondSibling);
          });
        });
      },
    );
  });
});
