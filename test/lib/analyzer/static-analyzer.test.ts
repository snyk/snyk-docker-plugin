#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { test } from "tap";
import { Docker } from "../../../lib/docker";

test("static analyze correctness", async (t) => {
  const examples = [
    {
      targetImage: "nginx:1.13.10",
      txtPaths: ["var/lib/apt/extended_states", "var/lib/dpkg/status"],
      md5: { "bin/ls": "0b19809bab331d70fb9983a0b9866290" },
    },
  ];

  const txtPaths = [
    "lib/apk/db/installed",
    "var/lib/dpkg/status",
    "var/lib/apt/extended_states",
  ];

  const md5Paths = ["bin/ls"];

  for (const example of examples) {
    await t.test(example.targetImage, async (t) => {
      const docker = new Docker(example.targetImage);
      const result = await docker.extract(txtPaths, md5Paths);
      for (const txtPath of example.txtPaths) {
        if (!Reflect.has(result.txt, txtPath)) {
          t.fail(`Expected text file not found ${txtPath}`);
        }
      }
      for (const md5Filename of Object.keys(example.md5)) {
        if (!Object.keys(result.md5).includes(md5Filename)) {
          t.fail(`Expected MD5 file not found ${md5Filename}`);
        }
        if (result.md5[md5Filename] !== example.md5[md5Filename]) {
          t.fail(`Wrong MD5 sum value for ${md5Filename}`);
        }
      }
    });
  }
});
