import {
  getImageIdFromManifest,
  getManifestLayers,
} from "../../../../lib/extractor/oci-archive";

describe("oci-archive index", () => {
  describe("getManifestLayers", () => {
    it("should return layer digests", () => {
      const manifest = {
        schemaVersion: "2",
        layers: [
          { digest: "sha256:layer1digest" },
          { digest: "sha256:layer2digest" },
          { digest: "sha256:layer3digest" },
        ],
        config: { digest: "sha256:configdigest" },
      };

      const result = getManifestLayers(manifest);

      expect(result).toEqual([
        "sha256:layer1digest",
        "sha256:layer2digest",
        "sha256:layer3digest",
      ]);
    });

    it("should handle empty layers array", () => {
      const manifest = {
        schemaVersion: "2",
        layers: [],
        config: { digest: "sha256:configdigest" },
      };

      const result = getManifestLayers(manifest);

      expect(result).toEqual([]);
    });
  });

  describe("getImageIdFromManifest", () => {
    it("should return config digest", () => {
      const manifest = {
        schemaVersion: "2",
        layers: [],
        config: { digest: "sha256:configdigest123456" },
      };

      const result = getImageIdFromManifest(manifest);

      expect(result).toBe("sha256:configdigest123456");
    });

    it("should throw error when config is missing", () => {
      const manifest = {
        schemaVersion: "2",
        layers: [],
      } as any;

      expect(() => getImageIdFromManifest(manifest)).toThrow(
        "Failed to extract image ID from archive manifest",
      );
    });

    it("should return undefined when config.digest is missing", () => {
      const manifest = {
        schemaVersion: "2",
        layers: [],
        config: {} as any,
      };

      const result = getImageIdFromManifest(manifest);
      expect(result).toBeUndefined();
    });

    it("should throw error when accessing config fails", () => {
      const manifest = {
        schemaVersion: "2",
        layers: [],
        get config(): { digest: string } {
          throw new Error("Cannot access config");
        },
      };

      expect(() => getImageIdFromManifest(manifest)).toThrow(
        "Failed to extract image ID from archive manifest",
      );
    });
  });
});
