import { Buffer } from "buffer";
import * as crypto from "crypto";
import { __metadata } from "tslib";
import {
  getDependencyFromPomProperties,
  jarFilesToScannedProjects,
  parsePomProperties,
} from "../../../lib/analyzer/applications/java";
import { getTextFromFixture } from "../../util";

describe("jarFilesToScannedProjects function", () => {
  // Arrange
  const bufferedDigest = Buffer.from(
    "485de3a253e23f645037828c07f1d7f1af40763a",
  );
  let hashedBuffer = crypto.createHash("sha1");
  hashedBuffer.setEncoding("hex");
  hashedBuffer.update(bufferedDigest);
  hashedBuffer.end();
  hashedBuffer = hashedBuffer.read().toString("hex");

  const filePathToContent = {
    "/libs/another_dir/test.jar": bufferedDigest,
  };

  it("should return expected scannedProject[] result", async () => {
    // Act
    const result = await jarFilesToScannedProjects(
      filePathToContent,
      "image-name",
      0, // we don't want to unpack any fat jars
    );

    // Assert
    expect(result[0].facts[0].type).toEqual("jarFingerprints");
    expect(result[0].facts[0].data.fingerprints[0].location).toEqual(
      "/libs/another_dir/test.jar",
    );
    expect(result[0].facts[0].data.fingerprints[0].digest).toEqual(
      hashedBuffer,
    );
    expect(result[0].identity.type).toEqual("maven");
    expect(result[0].identity.targetFile).toEqual("/libs/another_dir");
  });

  it("should catch errors with admzip and continue", async () => {
    // Act
    const result = await jarFilesToScannedProjects(
      filePathToContent,
      "image-name",
      1, // we want to ensure unpacking to "trip" admzip
    );

    // Assert
    expect(result[0].facts[0].type).toEqual("jarFingerprints");
    expect(result[0].facts[0].data.fingerprints[0].location).toEqual(
      "/libs/another_dir/test.jar",
    );
    expect(result[0].facts[0].data.fingerprints[0].digest).toEqual(
      hashedBuffer,
    );
    expect(result[0].identity.type).toEqual("maven");
    expect(result[0].identity.targetFile).toEqual("/libs/another_dir");
  });
});

describe("parsePomProperties function", () => {
  describe("with a valid pom.properties dependency file", () => {
    const fixture = getTextFromFixture("pom-properties/valid.pom.properties");
    const path = "/path/to/package-dependency-1.0.0.jar";
    const parsed = parsePomProperties(fixture);

    it("parsed output includes all required properties", () => {
      expect(parsed).toEqual(
        expect.objectContaining({
          name: "org.test.dependency",
          parentName: "org.test",
          version: "1.0.0",
        }),
      );
    });

    it("ignores superfluous lines in pom.properties", () => {
      expect(Object.keys(parsed)).toHaveLength(3);
    });
  });

  describe("with an invalid pom.properties dependency file", () => {
    it("returns null", () => {
      const fixture = getTextFromFixture(
        "pom-properties/invalid.pom.properties",
      );
      const path = "/path/to/org.test.dependency-1.0.0.jar";
      const dep = getDependencyFromPomProperties(fixture, path);
      expect(dep).toBeNull();
    });
  });
});

describe("getDependencyFromPomProperties function", () => {
  const fixture = getTextFromFixture("pom-properties/valid.pom.properties");
  const path = "/path/to/package-dependency-1.0.0.jar";
  const dep = parsePomProperties(fixture);

  it("returns a dep as expected", () => {
    const dep = getDependencyFromPomProperties(fixture, path);
    expect(dep).not.toBeNull();
  });

  it("returns null when the dependency references the JAR", () => {
    const path = "/path/to/org.test.dependency-1.0.0.jar";
    const dep = getDependencyFromPomProperties(fixture, path);
    expect(dep).toBeNull();
  });

  it("returns null when the pom.properties file has a required field missing", () => {
    const fixture = getTextFromFixture(
      "pom-properties/incomplete.pom.properties",
    );
    const path = "/path/to/org.test.dependency-1.0.0.jar";
    const dep = getDependencyFromPomProperties(fixture, path);
    expect(dep).toBeNull();
  });
});
