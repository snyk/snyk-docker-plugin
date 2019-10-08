#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as path from "path";
import { test } from "tap";
import * as plugin from "../../lib";
import { ImageType } from "../../lib/types";

const getFixture = (fixturePath) =>
  path.join(__dirname, "../fixtures/docker-archives", fixturePath);

test("static analysis builds the expected response", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "node:doesnotexist";
  const dockerfile = undefined;
  const pluginOptionsWithSkopeoCopy = {
    staticAnalysisOptions: {
      imagePath: getFixture("skopeo-copy/nginx.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginOptionsWithDockerSave = {
    staticAnalysisOptions: {
      imagePath: getFixture("docker-save/nginx.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResultWithSkopeoCopy = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptionsWithSkopeoCopy,
  );

  const pluginResultWithDockerSave = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptionsWithDockerSave,
  );

  // Test the skopeo-copy result.
  t.ok(
    "manifestFiles" in pluginResultWithSkopeoCopy &&
      "package" in pluginResultWithSkopeoCopy &&
      "plugin" in pluginResultWithSkopeoCopy,
    "Has the expected result properties",
  );

  t.deepEqual(
    pluginResultWithSkopeoCopy.manifestFiles,
    [],
    "Empty manifest files",
  );
  t.same(
    pluginResultWithSkopeoCopy.plugin.dockerImageId,
    thisIsJustAnImageIdentifierInStaticAnalysis,
    "The image ID matches",
  );
  t.same(
    pluginResultWithSkopeoCopy.plugin.packageManager,
    "deb",
    "Correct package manager detected",
  );
  t.deepEqual(
    pluginResultWithSkopeoCopy.plugin.imageLayers,
    ["ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9.tar"],
    "Layers are read correctly",
  );
  t.ok(
    pluginResultWithSkopeoCopy.package.dependencies &&
      "adduser" in pluginResultWithSkopeoCopy.package.dependencies,
    "Contains some expected dependency",
  );

  // Test the docker-save result.
  t.deepEqual(
    pluginResultWithDockerSave.plugin.imageLayers,
    [
      "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
    ],
    "Layers are read correctly",
  );

  t.deepEqual(
    pluginResultWithSkopeoCopy.package.dependencies,
    pluginResultWithDockerSave.package.dependencies,
    "The plugin scans both skopeo-copy and docker-save archives the same way",
  );
});
