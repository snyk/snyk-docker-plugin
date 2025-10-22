import { compress as zstdCompress } from "@mongodb-js/zstd";
import { ExtractedLayers } from "../../../../lib/extractor/types";
import {
  getChiselManifestAction,
  getChiselManifestContent,
} from "../../../../lib/inputs/chisel/static";

/**
 * Helper to compress data with zstd for testing.
 */
async function compressZstd(data: string): Promise<Buffer> {
  const buffer = Buffer.from(data, "utf8");
  const compressed = await zstdCompress(new Uint8Array(buffer));
  return Buffer.from(compressed);
}

describe("chisel static extraction", () => {
  describe("getChiselManifestAction", () => {
    it("matches the correct file path", () => {
      expect(
        getChiselManifestAction.filePathMatches(
          "/var/lib/chisel/manifest.wall",
        ),
      ).toBe(true);
    });

    it("does not match incorrect paths", () => {
      expect(
        getChiselManifestAction.filePathMatches("/var/lib/chisel/other.file"),
      ).toBe(false);
      expect(
        getChiselManifestAction.filePathMatches("/var/lib/dpkg/status"),
      ).toBe(false);
      expect(getChiselManifestAction.filePathMatches("/var/lib/chisel/")).toBe(
        false,
      );
    });
  });

  describe("getChiselManifestContent()", () => {
    it("returns empty array when manifest file is not present", () => {
      const extractedLayers: ExtractedLayers = {};

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toEqual([]);
    });

    it("extracts packages from valid manifest", async () => {
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":5}
{"kind":"package","name":"base-files","version":"13.6ubuntu2","sha256":"301da02c1fa60d35714c289627b8cf5c0616c16acf6cb35b0c048b107f9f1460","arch":"arm64"}
{"kind":"package","name":"ca-certificates","version":"20241223","sha256":"eb3b40012c23d356bf126319b4a6154b3afa1247e41e9c4803a4271d3fc829bf","arch":"all"}
{"kind":"slice","name":"base-files_chisel"}
{"kind":"path","path":"/var/lib/chisel/manifest.wall","mode":"0644","slices":["base-files_chisel"]}`;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        kind: "package",
        name: "base-files",
        version: "13.6ubuntu2",
        sha256:
          "301da02c1fa60d35714c289627b8cf5c0616c16acf6cb35b0c048b107f9f1460",
        arch: "arm64",
      });
      expect(result[1]).toEqual({
        kind: "package",
        name: "ca-certificates",
        version: "20241223",
        sha256:
          "eb3b40012c23d356bf126319b4a6154b3afa1247e41e9c4803a4271d3fc829bf",
        arch: "all",
      });
    });

    it("ignores non-package entries", async () => {
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":6}
{"kind":"package","name":"test-pkg","version":"1.0","sha256":"abc123","arch":"amd64"}
{"kind":"slice","name":"test_slice"}
{"kind":"content","slice":"test_slice","path":"/test"}
{"kind":"path","path":"/test","mode":"0755","slices":["test_slice"]}`;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toHaveLength(1);
      expect(result[0].kind).toBe("package");
      expect(result[0].name).toBe("test-pkg");
    });

    it("handles empty manifest (only header)", async () => {
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":1}`;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toEqual([]);
    });

    it("handles manifest with empty and whitespace lines", async () => {
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":3}

{"kind":"package","name":"test-pkg","version":"1.0","sha256":"abc123","arch":"amd64"}
   
\t
 `;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("test-pkg");
    });

    it("skips malformed JSON lines and continues processing", async () => {
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":4}
{"kind":"package","name":"pkg1","version":"1.0","sha256":"abc","arch":"amd64"}
{invalid json line}
{"kind":"package","name":"pkg2","version":"2.0","sha256":"def","arch":"amd64"}`;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      // Should get the two valid packages, skipping the malformed line
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("pkg1");
      expect(result[1].name).toBe("pkg2");
    });

    it("returns empty array for corrupted compressed data", () => {
      const corruptedData = Buffer.from("not valid zstd data");
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": corruptedData,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toEqual([]);
    });

    it("skips packages with missing or empty required fields", async () => {
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":9}
{"kind":"package","version":"1.0","sha256":"abc","arch":"amd64"}
{"kind":"package","name":"pkg1","sha256":"abc","arch":"amd64"}
{"kind":"package","name":"pkg2","version":"1.0","arch":"amd64"}
{"kind":"package","name":"pkg3","version":"1.0","sha256":"abc"}
{"kind":"package","name":"","version":"1.0","sha256":"abc","arch":"amd64"}
{"kind":"package","name":"pkg4","version":"","sha256":"abc","arch":"amd64"}
{"kind":"package","name":"pkg5","version":"1.0","sha256":"","arch":"amd64"}
{"kind":"package","name":"pkg6","version":"1.0","sha256":"abc","arch":""}
{"kind":"package","name":"valid-pkg","version":"1.0","sha256":"def","arch":"amd64"}`;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("valid-pkg");
    });

    it("extracts manifest alongside other layer data", async () => {
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":2}
{"kind":"package","name":"test-pkg","version":"1.0","sha256":"abc","arch":"amd64"}`;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
        "/other/path": {
          "other-action": Buffer.from("other data"),
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("test-pkg");
    });

    it("handles large manifests efficiently", async () => {
      // Generate a manifest with many packages
      const packages: string[] = [];
      for (let i = 0; i < 100; i++) {
        packages.push(
          `{"kind":"package","name":"pkg${i}","version":"1.0.${i}","sha256":"abc${i}","arch":"amd64"}`,
        );
      }
      const manifest = `{"jsonwall":"1.0","schema":"1.0","count":${
        packages.length + 1
      }}\n${packages.join("\n")}`;

      const compressedManifest = await compressZstd(manifest);
      const extractedLayers: ExtractedLayers = {
        "/var/lib/chisel/manifest.wall": {
          "chisel-manifest": compressedManifest,
        },
      };

      const result = getChiselManifestContent(extractedLayers);

      expect(result).toHaveLength(100);
      expect(result[0].name).toBe("pkg0");
      expect(result[99].name).toBe("pkg99");
    });
  });
});
