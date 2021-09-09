import { Buffer } from "buffer";
import * as crypto from "crypto";
import { jarFilesToScannedProjects } from "../../../lib/analyzer/applications/java";
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
