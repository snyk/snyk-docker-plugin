import { ExtractedLayers } from "../../../../lib/extractor/types";
import {
  getSpdxFileContentAction,
  getSpdxFileContents,
} from "../../../../lib/inputs/spdx/static";

describe("SPDX static input extraction", () => {
  describe("getSpdxFileContentAction", () => {
    it("matches SPDX file paths in /docker/sbom/", () => {
      expect(
        getSpdxFileContentAction.filePathMatches(
          "/docker/sbom/python/spdx.python.json",
        ),
      ).toBe(true);

      expect(
        getSpdxFileContentAction.filePathMatches(
          "/docker/sbom/pkg-binutils/spdx.pkg-binutils.json",
        ),
      ).toBe(true);

      expect(
        getSpdxFileContentAction.filePathMatches(
          "/docker/sbom/curl/spdx.curl.json",
        ),
      ).toBe(true);
    });

    it("does not match non-SPDX files", () => {
      expect(getSpdxFileContentAction.filePathMatches("/etc/os-release")).toBe(
        false,
      );

      expect(
        getSpdxFileContentAction.filePathMatches("/app/package.json"),
      ).toBe(false);

      expect(
        getSpdxFileContentAction.filePathMatches("/lib/apk/db/installed"),
      ).toBe(false);
    });

    it("does not match SPDX-like paths outside /docker/sbom/", () => {
      expect(
        getSpdxFileContentAction.filePathMatches("/other/sbom/spdx.test.json"),
      ).toBe(false);

      expect(
        getSpdxFileContentAction.filePathMatches("/app/spdx.data.json"),
      ).toBe(false);
    });

    it("requires 'spdx.' in the filename", () => {
      expect(
        getSpdxFileContentAction.filePathMatches(
          "/docker/sbom/python/metadata.json",
        ),
      ).toBe(false);

      expect(
        getSpdxFileContentAction.filePathMatches(
          "/docker/sbom/python/package.json",
        ),
      ).toBe(false);
    });

    it("has correct actionName", () => {
      expect(getSpdxFileContentAction.actionName).toBe("spdx-files");
    });
  });

  describe("getSpdxFileContents()", () => {
    it("extracts SPDX file contents from extractedLayers", () => {
      const extractedLayers: ExtractedLayers = {
        "/docker/sbom/python/spdx.python.json": {
          "spdx-files": '{"spdxVersion": "SPDX-2.3", "packages": []}',
        },
        "/docker/sbom/curl/spdx.curl.json": {
          "spdx-files":
            '{"spdxVersion": "SPDX-2.3", "packages": [{"name": "curl"}]}',
        },
        "/etc/os-release": {
          "os-release": "NAME=Alpine",
        },
      };

      const result = getSpdxFileContents(extractedLayers);

      expect(result).toHaveLength(2);
      expect(result[0]).toContain('"spdxVersion": "SPDX-2.3"');
      expect(result[1]).toContain('"spdxVersion": "SPDX-2.3"');
      expect(result[1]).toContain('"name": "curl"');
    });

    it("returns empty array when no SPDX files present", () => {
      const extractedLayers: ExtractedLayers = {
        "/etc/os-release": {
          "os-release": "NAME=Alpine",
        },
        "/lib/apk/db/installed": {
          "apk-db": "P:alpine-baselayout\nV:3.2.0",
        },
      };

      const result = getSpdxFileContents(extractedLayers);

      expect(result).toHaveLength(0);
      expect(result).toEqual([]);
    });

    it("handles missing actionName gracefully", () => {
      const extractedLayers: ExtractedLayers = {
        "/docker/sbom/python/spdx.python.json": {
          "wrong-action": "content", // Wrong action name
        },
      };

      const result = getSpdxFileContents(extractedLayers);

      expect(result).toHaveLength(0);
    });

    it("handles non-string content gracefully", () => {
      const extractedLayers: ExtractedLayers = {
        "/docker/sbom/python/spdx.python.json": {
          "spdx-files": 12345, // Not a string
        },
      };

      const result = getSpdxFileContents(extractedLayers);

      expect(result).toHaveLength(0);
    });

    it("extracts content only from matching paths", () => {
      const extractedLayers: ExtractedLayers = {
        "/docker/sbom/python/spdx.python.json": {
          "spdx-files": '{"valid": "spdx"}',
        },
        "/other/path/spdx.test.json": {
          "other-action": '{"should": "ignore"}',
        },
      };

      const result = getSpdxFileContents(extractedLayers);

      expect(result).toHaveLength(1);
      expect(result[0]).toContain('"valid": "spdx"');
    });

    it("handles multiple SPDX files from different layers", () => {
      const extractedLayers: ExtractedLayers = {
        "/docker/sbom/python/spdx.python.json": {
          "spdx-files": '{"package": "python"}',
        },
        "/docker/sbom/curl/spdx.curl.json": {
          "spdx-files": '{"package": "curl"}',
        },
        "/docker/sbom/openssl/spdx.openssl.json": {
          "spdx-files": '{"package": "openssl"}',
        },
      };

      const result = getSpdxFileContents(extractedLayers);

      expect(result).toHaveLength(3);
      expect(
        result.some((content) => content.includes('"package": "python"')),
      ).toBe(true);
      expect(
        result.some((content) => content.includes('"package": "curl"')),
      ).toBe(true);
      expect(
        result.some((content) => content.includes('"package": "openssl"')),
      ).toBe(true);
    });
  });
});
