import { ExtractedLayers } from "../../../../lib/extractor/types";
import {
  getBinariesHashes,
  getNodeBinariesFileContentAction,
  getOpenJDKBinariesFileContentAction,
} from "../../../../lib/inputs/binaries/static";
import { streamToSha256 } from "../../../../lib/stream-utils";

describe("lib/inputs/binaries/static", () => {
  describe("getNodeBinariesFileContentAction", () => {
    it("has the correct metadata", () => {
      expect(getNodeBinariesFileContentAction.actionName).toBe("node");
      expect(getNodeBinariesFileContentAction.callback).toBe(streamToSha256);
    });

    it("matches paths ending with 'node'", () => {
      expect(
        getNodeBinariesFileContentAction.filePathMatches("/usr/local/bin/node"),
      ).toBe(true);
      expect(
        getNodeBinariesFileContentAction.filePathMatches("/bin/node"),
      ).toBe(true);
      expect(
        getNodeBinariesFileContentAction.filePathMatches("/usr/bin/nodejs"),
      ).toBe(false);
    });
  });

  describe("getOpenJDKBinariesFileContentAction", () => {
    it("has the correct metadata", () => {
      expect(getOpenJDKBinariesFileContentAction.actionName).toBe("java");
      expect(getOpenJDKBinariesFileContentAction.callback).toBe(streamToSha256);
    });

    it("matches paths ending with 'java'", () => {
      expect(
        getOpenJDKBinariesFileContentAction.filePathMatches("/usr/bin/java"),
      ).toBe(true);
      expect(
        getOpenJDKBinariesFileContentAction.filePathMatches("/bin/java"),
      ).toBe(true);
      expect(
        getOpenJDKBinariesFileContentAction.filePathMatches("/usr/bin/javaw"),
      ).toBe(false);
    });
  });

  describe("getBinariesHashes", () => {
    it("returns an empty array for empty extracted layers", () => {
      const extractedLayers: ExtractedLayers = {};
      const result = getBinariesHashes(extractedLayers);
      expect(result).toEqual([]);
    });

    it("collects unique hashes from node and java entries", () => {
      const extractedLayers: ExtractedLayers = {
        "/usr/local/bin/node": { node: "hash-node-1" },
        "/usr/bin/java": { java: "hash-java-1" },
        "/opt/alt/node": { node: "hash-node-1" }, // duplicate should be deduped
        "/some/other": { other: "hash-other-1" }, // ignored
        "/another/java": { java: "hash-java-2" },
      };

      const result = getBinariesHashes(extractedLayers);

      // order is not guaranteed; compare as sets
      expect(result.sort()).toEqual(
        ["hash-node-1", "hash-java-1", "hash-java-2"].sort(),
      );
    });

    it("ignores unrelated actions", () => {
      const extractedLayers: ExtractedLayers = {
        "/whatever": { python: "hash-python-1", jar: "hash-jar-1" },
      };

      const result = getBinariesHashes(extractedLayers);
      expect(result).toEqual([]);
    });

    it("throws if a matched action value is not a string", () => {
      const extractedLayers: ExtractedLayers = {
        "/usr/local/bin/node": { node: Buffer.from("not-a-string") as any },
      };

      expect(() => getBinariesHashes(extractedLayers)).toThrowError(
        "expected string",
      );
    });
  });
});
