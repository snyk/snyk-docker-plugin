#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { test } from "tap";

import * as plugin from "../../lib";

test("plugin recognises experimenal flag", async (t) => {
  const imageName = "doesn't matter";
  const dockerfilePath = "unused";
  const options = { experimental: true };

  await t.rejects(
    () => plugin.inspect(imageName, dockerfilePath, options),
    new Error("not implemented"),
    "experimental scanning not implemented yet",
  );
});
