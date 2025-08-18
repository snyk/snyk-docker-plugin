import { getContentAsString, isWhitedOutFile } from "../../../lib/extractor";
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
});

describe("isWhitedOutFile", () => {
  test("should return true for files containing .wh. in their path", () => {
    expect(isWhitedOutFile("/etc/.wh.hosts")).toBe(true);
    expect(isWhitedOutFile("/var/lib/.wh.data")).toBe(true);
    expect(isWhitedOutFile("/.wh.config")).toBe(true);
  });

  test("should return false for files not containing .wh.", () => {
    expect(isWhitedOutFile("/etc/hosts")).toBe(false);
    expect(isWhitedOutFile("")).toBe(false);
    expect(isWhitedOutFile("/")).toBe(false);
  });

  test("should return false for similar but different patterns", () => {
    // make sure the dots are literal and not match all
    expect(isWhitedOutFile("/etc/wh.hosts")).toBe(false);
    expect(isWhitedOutFile("/etc/.whosts")).toBe(false);
    expect(isWhitedOutFile("/etc/whhosts")).toBe(false);

    // dots in wrong places
    expect(isWhitedOutFile("/etc/.w.h.hosts")).toBe(false);
    expect(isWhitedOutFile("/etc/..wh..hosts")).toBe(false);

    // case sensitive
    expect(isWhitedOutFile("/etc/.WH.hosts")).toBe(false);
    expect(isWhitedOutFile("/etc/.Wh.hosts")).toBe(false);
  });

  test("should handle .wh. at different positions", () => {
    expect(isWhitedOutFile(".wh.start")).toBe(true);
    expect(isWhitedOutFile("middle.wh.file")).toBe(false);
    expect(isWhitedOutFile("end.wh.")).toBe(false);
    expect(isWhitedOutFile("/deeply/nested/path/.wh.present")).toBe(true);
    expect(isWhitedOutFile("/the/.wh./in/path/present")).toBe(false);

  });
});
