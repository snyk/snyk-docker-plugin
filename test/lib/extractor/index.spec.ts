import { getContentAsString } from "../../../lib/extractor";
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
