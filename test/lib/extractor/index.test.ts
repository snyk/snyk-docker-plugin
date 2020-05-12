import { test } from "tap";
import { getContentAsString } from "../../../lib/extractor";
import { ExtractAction, ExtractedLayers } from "../../../lib/extractor/types";

test("getContentAsString() does matches when a pattern is used in the extract action", async (t) => {
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
  t.same(result, "Hello, world!", "extracted string matches");
});
