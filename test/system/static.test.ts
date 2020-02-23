#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as path from "path";
import { test } from "tap";
import * as plugin from "../../lib";
import { ImageType, PluginResponseStatic } from "../../lib/types";

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

test("omitting required options for static analysis", async (t) => {
  const emptyOptions = {
    staticAnalysisOptions: {},
  };
  const targetFile = undefined;
  await t.rejects(
    plugin.inspect("nginx:latest", targetFile, emptyOptions),
    Error("Missing required parameters for static analysis"),
    "static analysis requires parameters",
  );

  const onlyPathOptions = {
    staticAnalysisOptions: {
      imagePath: "/var/tmp/image.nonexistent",
    },
  };
  await t.rejects(
    plugin.inspect("nginx:latest", targetFile, onlyPathOptions),
    Error("Missing required parameters for static analysis"),
    "static analysis rejects on having imagePath but missing imageType",
  );

  const onlyTypeOptions = {
    staticAnalysisOptions: {
      imageType: ImageType.DockerArchive,
    },
  };
  await t.rejects(
    plugin.inspect("nginx:latest", targetFile, onlyTypeOptions),
    Error("Missing required parameters for static analysis"),
    "static analysis rejects on having imageTypee but missing imagePath",
  );
});

test("/etc/os-release links to /usr/lib/os-release", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "node:doesnotexist";
  const dockerfile = undefined;
  const pluginOptionsWithDockerSave = {
    staticAnalysisOptions: {
      imagePath: getFixture("docker-save/nginx-os-release-link.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResultWithDockerSave = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptionsWithDockerSave,
  );

  t.deepEqual(pluginResultWithDockerSave.package.targetOS, {
    name: "debian",
    version: "10",
  });
});

test("static analysis provides hashes for key binaries", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "node:doesnotexist";
  const dockerfile = undefined;
  const pluginOptionsWithSkopeoCopy = {
    staticAnalysisOptions: {
      imagePath: getFixture("skopeo-copy/nodes-fake-multi.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResultWithSkopeoCopy = (await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptionsWithSkopeoCopy,
  )) as PluginResponseStatic;

  t.equals(
    pluginResultWithSkopeoCopy.hashes.length,
    4,
    "found four key binaries",
  );
  const expectedHashes = [
    "f20f16782d8c442142560d1dad09561161fb495179751db200d9db6caf6ad832",
    "c7f4fefb1e2994b8ac23134ea9c2b7aa8b2d088b8863fa33012ca7b8824e1bed",
    "0198b003dfe9fff4ee28ca7d75893bff7375dedd1a969c781771a4b34443fb33",
    "62f8defe3fe085af9b6e48f85ffb90a863c44d53b9c3f4f237b04c232f350083",
  ];
  t.deepEqual(
    pluginResultWithSkopeoCopy.hashes.sort(),
    expectedHashes.sort(),
    "all key binaries match hashes",
  );
});
