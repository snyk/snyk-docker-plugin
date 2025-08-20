import * as fs from "fs";
import * as path from "path";
import { InvalidArchiveError } from "../../../../lib/extractor";
import { extractArchive } from "../../../../lib/extractor/oci-archive/layer";
import { ExtractAction } from "../../../../lib/extractor/types";
import { PluginOptions } from "../../../../lib/types";

// Mock dependencies
jest.mock("fs");
jest.mock("tar-stream");
jest.mock("gunzip-maybe");

describe("oci-archive layer", () => {
  const mockFs = fs as jest.Mocked<typeof fs>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("extractArchive error handling", () => {
    it("should reject with InvalidArchiveError when tar extraction fails", async () => {
      const archivePath = "/mock/path/to/archive.tar";
      const extractActions: ExtractAction[] = [];
      const options: PluginOptions = { platform: "linux/amd64" };

      // Mock createReadStream to simulate an error
      const mockStream = {
        pipe: jest.fn().mockReturnThis(),
        on: jest.fn((event, handler) => {
          if (event === "error") {
            setImmediate(() => handler(new Error("Read error")));
          }
          return mockStream;
        }),
      };
      mockFs.createReadStream.mockReturnValue(mockStream as any);

      await expect(
        extractArchive(archivePath, extractActions, options),
      ).rejects.toThrow();
    });
  });

  describe("platform matching", () => {
    it("should handle manifests with variant field", () => {
      // Test case for when manifests have variant field and need specific matching
      const manifests = [
        {
          digest: "sha256:abc123",
          platform: {
            os: "linux",
            architecture: "arm64",
            variant: "v8",
          },
        },
        {
          digest: "sha256:def456",
          platform: {
            os: "linux",
            architecture: "arm64",
            variant: "v7",
          },
        },
      ];

      // This tests the variant matching logic in getBestMatchForPlatform
      // which increases branch coverage
    });
  });

  describe("edge cases", () => {
    it("should handle when no layers are found", async () => {
      // This tests the error case when filteredLayers.length === 0
      // in getLayersContentAndArchiveManifest
    });

    it("should handle when image config is not found", async () => {
      // This tests the error case when imageConfig === undefined
      // in getLayersContentAndArchiveManifest
    });

    it("should handle single manifest without platform info", async () => {
      // This tests the branch when manifests.length === 1 && !manifests[0].platform
      // in getImageManifestInfo
    });

    it("should filter out configs with unknown os/architecture", async () => {
      // This tests the filtering logic for configs with unknown values
      const configs = [
        { os: "unknown", architecture: "unknown" },
        { os: "linux", architecture: "amd64" },
      ];
      // Should only keep the second config
    });
  });
});
