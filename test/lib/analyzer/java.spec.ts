import * as crypto from "crypto";
import { readFileSync } from "fs";
import { __metadata } from "tslib";
import {
  getCoordsFromPomProperties,
  jarFilesToScannedResults,
  parsePomProperties,
} from "../../../lib/analyzer/applications/java";
import { getTextFromFixture } from "../../util";

describe("jarFilesToScannedResults function", () => {
  it("should return expected scannedProject[] result", async () => {
    // Arrange
    const buffered = readFileSync("test/fixtures/maven/fixture-1.0.0.jar");
    const filePathToContent = {
      "/lib/test/fixture-1.0.0.jar": buffered,
    };

    // Act
    const result = await jarFilesToScannedResults(
      filePathToContent,
      "image-name",
      0, // we don't want to include any nested JARs
    );

    // Assert
    expect(result[0].facts[0].type).toEqual("jarFingerprints");
    expect(result[0].facts[0].data.fingerprints[0].location).toEqual(
      "/lib/test/fixture-1.0.0.jar",
    );
    expect(result[0].facts[0].data.fingerprints[0].digest).toBeNull();
    expect(result[0].identity.type).toEqual("maven");
    expect(result[0].identity.targetFile).toEqual("/lib/test");
  });

  it("should catch errors with admzip and continue", async () => {
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
      "/lib/test/fixture-1.0.0.jar": bufferedDigest,
    };

    // Act
    const result = await jarFilesToScannedResults(
      filePathToContent,
      "image-name",
      0, // we always unpack so will still "trip" admzip
    );

    // Assert
    expect(result[0].facts[0].type).toEqual("jarFingerprints");
    expect(result[0].facts[0].data.fingerprints[0].location).toEqual(
      "/lib/test/fixture-1.0.0.jar",
    );
    expect(result[0].facts[0].data.fingerprints[0].digest).toEqual(
      hashedBuffer,
    );
    expect(result[0].identity.type).toEqual("maven");
    expect(result[0].identity.targetFile).toEqual("/lib/test");
  });
});

describe("parsePomProperties function", () => {
  describe("with a valid pom.properties dependency file", () => {
    const fixture = getTextFromFixture("pom-properties/valid.pom.properties");
    const parsed = parsePomProperties(fixture);

    it("parsed output includes all required properties", () => {
      expect(parsed).toEqual(
        expect.objectContaining({
          artifactId: "org.test.dependency",
          groupId: "org.test",
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
      const coords = getCoordsFromPomProperties(fixture);
      expect(coords).toBeNull();
    });
  });
});

describe("getCoordsFromPomProperties function", () => {
  const fixture = getTextFromFixture("pom-properties/valid.pom.properties");

  it("returns a coord as expected", () => {
    const coords = getCoordsFromPomProperties(fixture);
    expect(coords).not.toBeNull();
  });

  it("returns null when the pom.properties file has a required field missing", () => {
    const fixture = getTextFromFixture(
      "pom-properties/incomplete.pom.properties",
    );
    const coords = getCoordsFromPomProperties(fixture);
    expect(coords).toBeNull();
  });
});
