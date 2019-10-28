#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { getManifestFiles } from "../../lib/index";

import { readFileSync } from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";
import * as subProcess from "../../lib/sub-process";

const getLSOutputFixture = (file: string) =>
  path.join(__dirname, "../fixtures/ls-output", file);

test("findGlobs", async (t) => {
  const stub = sinon.stub(subProcess, "execute");
  t.beforeEach(async () => {
    stub.resetHistory();
  });
  t.tearDown(() => {
    stub.restore();
  });

  // const targetImage = "some:image";
  // const docker = new Docker(targetImage);
  t.test(
    "find globs on ghost app using system files exclude glob ",
    async (t) => {
      stub.resolves({
        stdout: readFileSync(getLSOutputFixture("ghost-app.txt")).toString(),
      });

      const files = await getManifestFiles("blabla", {
        manifestGlobs: ["**/test-exclude-system.txt"],
        manifestExcludeGlobs: ["/sys/**"],
      });

      files.forEach((file) => {
        t.match(file, {
          name: /test-exclude-system\.txt/,
          path: /^(\/bin|\/)$/,
        });
        t.notMatch(file, { path: /\/sys/ });
      });
    },
  );
});
