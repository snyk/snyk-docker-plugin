import { Buffer } from "buffer";
import * as crypto from "crypto";
import { __metadata } from "tslib";
import {
  getDependenciesFromPomProperties,
  jarFilesToScannedProjects,
} from "../../../lib/analyzer/applications/java";
import { getTextFromFixture } from "../../util";

describe("jarFilesToScannedProjects function", () => {
  it("should return expected scannedProject[] result", async () => {
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
});

describe("getDependenciesFromPomProperties function", () => {
  class MockZippedEntry {
    private data: Buffer;
    constructor(value: string) {
      this.data = Buffer.from(value);
    }
    public getData() {
      return this.data;
    }
  }

  describe("with a valid pom.properties dependency file", () => {
    const fixture = getTextFromFixture("pom-properties/valid.pom.properties");
    const mockedZippedEntry = new MockZippedEntry(fixture);
    const path = "/path/to/package-dependency-1.0.0.jar";
    const deps = getDependenciesFromPomProperties(mockedZippedEntry, [], path);

    it("parser ignores superfluous lines in pom.properties", () => {
      expect(Object.keys(deps[0])).toHaveLength(3);
    });

    it("parsed output includes all required properties", () => {
      expect(deps[0]).toEqual(
        expect.objectContaining({
          name: "org.test.dependency",
          parentName: "org.test",
          version: "1.0.0",
        }),
      );
    });

    it("parser ignores the dependency when it references the parent package", () => {
      const path = "/path/to/org.test.dependency-1.0.0.jar";
      const deps = getDependenciesFromPomProperties(
        mockedZippedEntry,
        [],
        path,
      );
      expect(deps).toHaveLength(0);
    });
  });
});
