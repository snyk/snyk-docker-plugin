#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as minimatch from "minimatch";
import { test } from "tap";
import { getContentAsString } from "../../../lib/extractor";
import { ExtractAction, ExtractedLayers } from "../../../lib/extractor/types";

test("BUG: getContentAsString() does not match when a pattern is used in the extract action", async (t) => {
  const extractAction: ExtractAction = {
    actionName: "match-any-node",
    fileNamePattern: "**/node",
    filePathMatches: (filePath) =>
      minimatch(filePath, "**/node", { dot: true }),
  };
  const extractedLayers: ExtractedLayers = {
    "/var/lib/node": {
      "match-any-node": "Hello, world!",
    },
  };
  const result = getContentAsString(extractedLayers, extractAction);
  t.same(result, undefined, "BUG: extracted string should be Hello, world!");
});
