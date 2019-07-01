#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import * as crypto from "crypto";
import { test } from "tap";
import * as analyzer from "../../../lib/analyzer/hash-analyzer";
import { Docker } from "../../../lib/docker";

import * as minimatch from "minimatch";

test("analyze", async (t) => {
  t.true(minimatch("var/opt/bin/node", "**/node", { dot: true }));

  const docker = new Docker("alpine:2.6");

  docker.scanStaticalyIfNeeded([
    {
      name: "hash",
      pattern: "**/node",
      callback: (b) =>
        crypto
          .createHash("sha256")
          .update(b)
          .digest("hex"),
    },
  ]);

  const actual = await analyzer.analyze(docker);
  t.same(actual, {
    Image: "alpine:2.6",
    AnalyzeType: "Hash",
    Analysis: [],
  });
});
