import { getImageIdFromManifest } from "../../../../lib/extractor/docker-archive";
import { DockerArchiveManifest } from "../../../../lib/extractor/types";

describe("getImageIdFromManifest", () => {
  describe("when manifest config string contains algorithm prefix", () => {
    it("returns the imageId with prefix", () => {
      const manifest: DockerArchiveManifest = {
        Config:
          "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538.json",
        RepoTags: [],
        Layers: [],
      };

      const imageId = getImageIdFromManifest(manifest);
      expect(imageId).toEqual(
        "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
      );
    });
  });

  describe("when manifest config string does not contain algorithm prefix", () => {
    it("returns the imageId with prefix", () => {
      const manifest: DockerArchiveManifest = {
        Config:
          "2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538.json",
        RepoTags: [],
        Layers: [],
      };

      const imageId = getImageIdFromManifest(manifest);
      expect(imageId).toEqual(
        "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
      );
    });
  });
});
