import {
  getContentAsString,
  isWhitedOutFile,
  removeWhiteoutPrefix,
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

describe("removeWhiteoutPrefix", () => {
  test("should remove .wh. prefix from filenames without slashes", () => {
    expect(removeWhiteoutPrefix(".wh.hosts")).toBe("hosts");
    expect(removeWhiteoutPrefix(".wh.data")).toBe("data");
    expect(removeWhiteoutPrefix(".wh.config")).toBe("config");
    expect(removeWhiteoutPrefix(".wh.")).toBe("");
    expect(removeWhiteoutPrefix(".wh.file.txt")).toBe("file.txt");
  });

  test("should remove .wh. prefix after the last slash in paths", () => {
    expect(removeWhiteoutPrefix("/etc/.wh.hosts")).toBe("/etc/hosts");
    expect(removeWhiteoutPrefix("/var/lib/.wh.data")).toBe("/var/lib/data");
    expect(removeWhiteoutPrefix("/.wh.config")).toBe("/config");
    expect(removeWhiteoutPrefix("/deeply/nested/path/.wh.present")).toBe(
      "/deeply/nested/path/present",
    );
    expect(removeWhiteoutPrefix("/path/to/.wh.")).toBe("/path/to/");
  });

  test("should not modify files that don't have .wh. prefix in the correct position", () => {
    expect(removeWhiteoutPrefix("normal.file")).toBe("normal.file");
    expect(removeWhiteoutPrefix("/etc/hosts")).toBe("/etc/hosts");
    expect(removeWhiteoutPrefix("middle.wh.file")).toBe("middle.wh.file");
    expect(removeWhiteoutPrefix("/path/middle.wh.file")).toBe(
      "/path/middle.wh.file",
    );
    expect(removeWhiteoutPrefix(".whfile")).toBe(".whfile");
    expect(removeWhiteoutPrefix("/path/.whfile")).toBe("/path/.whfile");
    expect(removeWhiteoutPrefix("/path/has/.wh./in/middle")).toBe(
      "/path/has/.wh./in/middle",
    );
  });

  test("should handle edge cases", () => {
    expect(removeWhiteoutPrefix("")).toBe("");
    expect(removeWhiteoutPrefix("/")).toBe("/");
    expect(removeWhiteoutPrefix("//")).toBe("//");
    expect(removeWhiteoutPrefix("/.wh.")).toBe("/");
    expect(removeWhiteoutPrefix("//.wh.test")).toBe("//test");
  });

  test("should not remove .wh. that appears in the middle of paths", () => {
    expect(removeWhiteoutPrefix("/the/.wh./in/path/file")).toBe(
      "/the/.wh./in/path/file",
    );
    expect(removeWhiteoutPrefix("/path/.wh.dir/.wh.file")).toBe(
      "/path/.wh.dir/file",
    );
  });
});
