#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { test } from "tap";
import { getImageType } from "../../lib/image-type";
import { ImageType } from "../../lib/types";

test("getImageType() returns the expected transports", (t) => {
  t.plan(2);

  t.same(
    getImageType("nginx:latest"),
    ImageType.Identifier,
    "plain image identifier is handled",
  );
  t.same(
    getImageType("docker-archive:/tmp/nginx.tar"),
    ImageType.Identifier,
    "docker-archive is not yet handled",
  );
});
