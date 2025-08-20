import { PassThrough } from "stream";
import { ExtractedLayers } from "../../../../lib/extractor/types";
import {
  generateExtractAction,
  getMatchingFiles,
} from "../../../../lib/inputs/file-pattern/static";

describe("file-pattern static", () => {
  describe("generateExtractAction", () => {
    it("should exclude files matching exclusion patterns", async () => {
      const includeGlobs = ["**/*.json", "**/*.yaml"];
      const excludeGlobs = ["**/node_modules/**", "**/test/**"];

      const extractAction = generateExtractAction(includeGlobs, excludeGlobs);

      // Test that files in excluded paths are rejected
      expect(
        extractAction.filePathMatches("/app/node_modules/package.json"),
      ).toBe(false);
      expect(extractAction.filePathMatches("/test/fixtures/config.yaml")).toBe(
        false,
      );

      // Test that files not in excluded paths are accepted
      expect(extractAction.filePathMatches("/app/config.json")).toBe(true);
      expect(extractAction.filePathMatches("/src/settings.yaml")).toBe(true);
    });

    it("should handle multiple exclusion patterns", async () => {
      const includeGlobs = ["**/*"];
      const excludeGlobs = ["*.log", "*.tmp", "**/cache/**"];

      const extractAction = generateExtractAction(includeGlobs, excludeGlobs);

      expect(extractAction.filePathMatches("error.log")).toBe(false);
      expect(extractAction.filePathMatches("temp.tmp")).toBe(false);
      expect(extractAction.filePathMatches("/var/cache/data.txt")).toBe(false);
      expect(extractAction.filePathMatches("config.txt")).toBe(true);
    });

    it("should prioritize exclusion over inclusion", async () => {
      const includeGlobs = ["*.txt"];
      const excludeGlobs = ["secret.txt"];

      const extractAction = generateExtractAction(includeGlobs, excludeGlobs);

      expect(extractAction.filePathMatches("secret.txt")).toBe(false);
      expect(extractAction.filePathMatches("readme.txt")).toBe(true);
    });

    it("should handle stream to base64 conversion", async () => {
      const includeGlobs = ["*.txt"];
      const excludeGlobs = [];

      const extractAction = generateExtractAction(includeGlobs, excludeGlobs);

      const testData = "Hello, World!";
      const stream = new PassThrough();
      stream.end(Buffer.from(testData));

      const result = await extractAction.callback(stream, testData.length);
      expect(result).toBe(Buffer.from(testData).toString("base64"));
    });
  });

  describe("getMatchingFiles", () => {
    it("should throw an error when extracted data is not a string", () => {
      const extractedLayers: ExtractedLayers = {
        "/app/config.json": {
          "find-files-by-pattern": { invalid: "data" } as any,
        },
      };

      expect(() => getMatchingFiles(extractedLayers)).toThrow(
        "expected a string",
      );
    });

    it("should skip files with different action names", () => {
      const extractedLayers: ExtractedLayers = {
        "/app/config.json": {
          "other-action": "some-data",
          "find-files-by-pattern": "eyJjb25maWciOiAidGVzdCJ9", // {"config": "test"}
        },
        "/app/package.json": {
          "different-action": "other-data",
        },
      };

      const result = getMatchingFiles(extractedLayers);
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("config.json");
      expect(result[0].path).toBe("/app");
    });

    it("should handle multiple files with base64 content", () => {
      const extractedLayers: ExtractedLayers = {
        "/etc/config.yaml": {
          "find-files-by-pattern": Buffer.from("key: value").toString("base64"),
        },
        "/app/settings.json": {
          "find-files-by-pattern":
            Buffer.from('{"setting": true}').toString("base64"),
        },
      };

      const result = getMatchingFiles(extractedLayers);
      expect(result).toHaveLength(2);

      const configFile = result.find((f) => f.name === "config.yaml");
      expect(configFile?.path).toBe("/etc");
      expect(configFile?.contents).toBe(
        Buffer.from("key: value").toString("base64"),
      );

      const settingsFile = result.find((f) => f.name === "settings.json");
      expect(settingsFile?.path).toBe("/app");
      expect(settingsFile?.contents).toBe(
        Buffer.from('{"setting": true}').toString("base64"),
      );
    });
  });
});
