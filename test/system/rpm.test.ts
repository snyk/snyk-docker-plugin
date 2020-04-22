#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { ImageType } from "../../lib/types";

function getFixture(fixturePath): string {
  return path.join(__dirname, "../fixtures/docker-archives", fixturePath);
}

test("scanning an rpm-based image produces the expected response", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "amazonlinux:2";
  const dockerfile = undefined;
  const pluginOptions = {
    staticAnalysisOptions: {
      imagePath: getFixture("skopeo-copy/rpm.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResult = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptions,
  );

  t.same(
    pluginResult.plugin.dockerImageId,
    "7f335821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
    "The image ID matches",
  );
  t.same(
    pluginResult.plugin.packageManager,
    "rpm",
    "Correct package manager detected",
  );
  t.deepEqual(
    pluginResult.plugin.imageLayers,
    ["2943de48ac85f6eaeecbf35ed894375b5001e9001fd908e40d8e577b77e6bfeb.tar"],
    "Layers are read correctly",
  );

  const dependencies = Object.keys(
    pluginResult.scannedProjects[0].depTree.dependencies,
  );
  t.same(
    dependencies.length,
    104,
    "Contains the expected number of dependencies",
  );
});
