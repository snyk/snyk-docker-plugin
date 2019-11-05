#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import { tmpdir } from "os";
import { test } from "tap";
import { generateTempFileName } from "../../../lib/inputs/rpm/static";

test("generateTempFileName() tests", async (t) => {
  const firstGeneratedName = generateTempFileName();
  const secondGeneratedName = generateTempFileName();
  t.notEqual(
    firstGeneratedName,
    secondGeneratedName,
    "subsequent runs generate different names",
  );

  const nameStartingWithTmpDir = generateTempFileName();
  const tmpDir = tmpdir();
  t.ok(
    nameStartingWithTmpDir.startsWith(tmpDir),
    "generates a file name under tmpdir() when no path is specified",
  );

  const specificPath = "/var/tmp";
  const nameWithSpecificPath = generateTempFileName(specificPath);
  t.ok(
    nameWithSpecificPath.startsWith(specificPath),
    "generates a file name under the path specified",
  );
});
