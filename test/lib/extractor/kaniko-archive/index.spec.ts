import {
  getImageIdFromManifest,
  getManifestLayers,
} from "../../../../lib/extractor/kaniko-archive";
import { HashAlgorithm } from "../../../../lib/types";

describe("kaniko-archive index", () => {
  describe("getManifestLayers", () => {
    it("should return normalized layer paths", () => {
      const manifest = {
        Layers: ["./layer1.tar.gz", "layer2.tar.gz", "subdir/layer3.tar.gz"],
        Config: "config.json",
      };

      const result = getManifestLayers(manifest);

      expect(result).toEqual([
        "layer1.tar.gz",
        "layer2.tar.gz",
        "subdir/layer3.tar.gz",
      ]);
    });
  });

  describe("getImageIdFromManifest", () => {
    it("should return imageId with algorithm prefix when already included", () => {
      const manifest = {
        Layers: [],
        Config: "sha256:abcd1234567890",
      };

      const result = getImageIdFromManifest(manifest);

      expect(result).toBe("sha256:abcd1234567890");
    });

    it("should add sha256 prefix when not included", () => {
      const manifest = {
        Layers: [],
        Config: "abcd1234567890",
      };

      const result = getImageIdFromManifest(manifest);

      expect(result).toBe(`${HashAlgorithm.Sha256}:abcd1234567890`);
    });

    it("should throw error when Config is missing", () => {
      const manifest = {
        Layers: [],
      } as any;

      expect(() => getImageIdFromManifest(manifest)).toThrow(
        "Failed to extract image ID from archive manifest",
      );
    });

    it("should throw error when accessing Config fails", () => {
      const manifest = {
        Layers: [],
        get Config() {
          throw new Error("Cannot access Config");
        },
      };

      expect(() => getImageIdFromManifest(manifest)).toThrow(
        "Failed to extract image ID from archive manifest",
      );
    });
  });
});
