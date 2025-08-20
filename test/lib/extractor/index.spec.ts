import {
  getContentAsBuffer,
  getContentAsString,
  getUserInstructionLayersFromConfig,
} from "../../../lib/extractor";
import { ExtractAction, ExtractedLayers } from "../../../lib/extractor/types";

describe("index", () => {
  test("getContentAsString() does matches when a pattern is used in the extract action", async () => {
    const extractAction: ExtractAction = {
      actionName: "match-any-node",
      filePathMatches: (filePath) => filePath.endsWith("node"),
    };
    const extractedLayers: ExtractedLayers = {
      "/var/lib/node": {
        "match-any-node": "Hello, world!",
      },
    };
    const result = getContentAsString(extractedLayers, extractAction);

    //  extracted string matches
    expect(result).toEqual("Hello, world!");
  });

  describe("getUserInstructionLayersFromConfig", () => {
    test("returns empty array when history is missing", () => {
      const imageConfig = {
        // history is intentionally missing
      };

      const result = getUserInstructionLayersFromConfig(imageConfig);

      expect(result).toEqual([]);
    });

    test("returns empty array when history is null", () => {
      const imageConfig = {
        history: null,
      };

      const result = getUserInstructionLayersFromConfig(imageConfig);

      expect(result).toEqual([]);
    });

    test("returns user instruction layers when history exists", () => {
      const now = new Date();
      const fourHoursAgo = new Date(now.getTime() - 4 * 60 * 60 * 1000);
      const sixHoursAgo = new Date(now.getTime() - 6 * 60 * 60 * 1000);

      const imageConfig = {
        history: [
          {
            created: sixHoursAgo.toISOString(),
            created_by: "RUN apt-get update",
          },
          {
            created: fourHoursAgo.toISOString(),
            created_by: "RUN apt-get install",
          },
          { created: now.toISOString(), created_by: 'CMD ["nginx"]' },
        ],
      };

      const result = getUserInstructionLayersFromConfig(imageConfig);

      // Should return layers within 5 hours of the last layer
      expect(result).toHaveLength(2);
      expect(result[0].created_by).toBe("RUN apt-get install");
      expect(result[1].created_by).toBe('CMD ["nginx"]');
    });

    test("returns empty array when all layers are user instructions", () => {
      const now = new Date();

      const imageConfig = {
        history: [
          { created: now.toISOString(), created_by: "RUN apt-get update" },
          { created: now.toISOString(), created_by: "RUN apt-get install" },
          { created: now.toISOString(), created_by: 'CMD ["nginx"]' },
        ],
      };

      const result = getUserInstructionLayersFromConfig(imageConfig);

      // When all layers are within the time window, return empty array
      expect(result).toEqual([]);
    });
  });

  describe("getContentAsBuffer", () => {
    it("returns undefined when content is a string", () => {
      const extractAction: ExtractAction = {
        actionName: "test-action",
        filePathMatches: () => true,
      };
      const extractedLayers: ExtractedLayers = {
        "/test/file": {
          "test-action": "This is a string, not a buffer",
        },
      };

      const result = getContentAsBuffer(extractedLayers, extractAction);
      expect(result).toBeUndefined();
    });

    it("returns Buffer when content is a Buffer", () => {
      const testBuffer = Buffer.from("test content");
      const extractAction: ExtractAction = {
        actionName: "test-action",
        filePathMatches: () => true,
      };
      const extractedLayers: ExtractedLayers = {
        "/test/file": {
          "test-action": testBuffer,
        },
      };

      const result = getContentAsBuffer(extractedLayers, extractAction);
      expect(result).toEqual(testBuffer);
    });

    it("returns undefined when no matching file is found", () => {
      const extractAction: ExtractAction = {
        actionName: "test-action",
        filePathMatches: () => false,
      };
      const extractedLayers: ExtractedLayers = {
        "/test/file": {
          "test-action": Buffer.from("test"),
        },
      };

      const result = getContentAsBuffer(extractedLayers, extractAction);
      expect(result).toBeUndefined();
    });
  });

  describe("getContent edge cases", () => {
    it("returns undefined when action name is not found in extracted layers", () => {
      const extractAction: ExtractAction = {
        actionName: "missing-action",
        filePathMatches: () => true,
      };
      const extractedLayers: ExtractedLayers = {
        "/test/file": {
          "different-action": "content",
        },
      };

      const result = getContentAsString(extractedLayers, extractAction);
      expect(result).toBeUndefined();
    });

    it("returns undefined when extracted layers is empty", () => {
      const extractAction: ExtractAction = {
        actionName: "test-action",
        filePathMatches: () => true,
      };
      const extractedLayers: ExtractedLayers = {};

      const result = getContentAsString(extractedLayers, extractAction);
      expect(result).toBeUndefined();
    });
  });
});
