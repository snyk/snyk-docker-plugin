import { jarFilesToScannedProjects } from "../../../lib/analyzer/applications/java";

describe("jarFilesToScannedProjects function", () => {
  it("should return expected scannedProject[] result", async () => {
    const filePathToContent = {
      "/libs/another_dir/test.jar": "485de3a253e23f645037828c07f1d7f1af40763a",
    };

    const result = await jarFilesToScannedProjects(
      filePathToContent,
      "image-name",
    );
    expect(result[0].facts[0].type).toEqual("jarFingerprints");
    expect(result[0].facts[0].data.fingerprints[0].location).toEqual(
      "/libs/another_dir/test.jar",
    );
    expect(result[0].facts[0].data.fingerprints[0].digest).toEqual(
      "485de3a253e23f645037828c07f1d7f1af40763a",
    );
    expect(result[0].identity.type).toEqual("maven");
    expect(result[0].identity.targetFile).toEqual("/libs/another_dir");
  });
});
