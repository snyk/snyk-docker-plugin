import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { DepTree, ImageType, PluginResponseStatic } from "../../lib/types";

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

  const pluginOptionsWithCompressedSkopeoCopy = {
    staticAnalysisOptions: {
      imagePath: getFixture("skopeo-copy/nginx-compressed-layers.tar"),
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

  const pluginResultWithCompressedSkopeoCopy = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptionsWithCompressedSkopeoCopy,
  );

  const pluginResultWithDockerSave = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptionsWithDockerSave,
  );

  // Test the skopeo-copy result.
  t.ok(
    "scannedProjects" in pluginResultWithSkopeoCopy &&
      Array.isArray(pluginResultWithSkopeoCopy.scannedProjects) &&
      pluginResultWithSkopeoCopy.scannedProjects.length === 1 &&
      "plugin" in pluginResultWithSkopeoCopy,
    "Has the expected result properties",
  );

  t.same(
    pluginResultWithSkopeoCopy.scannedProjects[0].depTree.version,
    "doesnotexist",
    "Version matches",
  );
  t.same(
    pluginResultWithSkopeoCopy.plugin.dockerImageId,
    "ab56bba91343aafcdd94b7a44b42e12f32719b9a2b8579e93017c1280f48e8f3",
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
    pluginResultWithSkopeoCopy.scannedProjects[0].depTree.dependencies &&
      "adduser" in
        pluginResultWithSkopeoCopy.scannedProjects[0].depTree.dependencies,
    "Contains some expected dependency",
  );

  // Test the docker-save result.
  t.deepEqual(
    pluginResultWithDockerSave.plugin.imageLayers,
    [
      path.normalize(
        "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
      ),
    ],
    "Layers are read correctly",
  );

  t.deepEqual(
    pluginResultWithSkopeoCopy.scannedProjects[0].depTree.dependencies,
    pluginResultWithDockerSave.scannedProjects[0].depTree.dependencies,
    "The plugin scans both skopeo-copy and docker-save archives the same way",
  );

  t.deepEqual(
    pluginResultWithCompressedSkopeoCopy.scannedProjects[0].depTree
      .dependencies,
    pluginResultWithDockerSave.scannedProjects[0].depTree.dependencies,
    "The plugin scans both skopeo-copy and docker-save archives the same way",
  );
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

test("static analysis provides hashes for found openjdk binaries", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "openjdk:doesnotexist";
  const dockerfile = undefined;
  const pluginOptions = {
    staticAnalysisOptions: {
      imagePath: getFixture("docker-save/openjdk.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResult = (await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptions,
  )) as PluginResponseStatic;

  t.equals(pluginResult.hashes.length, 1, "found one openjdk key binary");
  const expectedHashes = [
    "004182a1acb5aad313f4554cbafe474a9bdc143260576ac3fa4ab388c3f40476",
  ];
  t.deepEqual(
    pluginResult.hashes,
    expectedHashes,
    "all key binaries match hashes",
  );
});

test("static analysis works for scratch images", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "busybox:1.31.1";
  const dockerfile = undefined;
  const pluginOptionsWithSkopeoCopy = {
    staticAnalysisOptions: {
      imagePath: getFixture("skopeo-copy/busybox.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResultWithSkopeoCopy = (await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptionsWithSkopeoCopy,
  )) as PluginResponseStatic;

  const depTree = pluginResultWithSkopeoCopy.scannedProjects[0]
    .depTree as DepTree;
  t.equals(
    pluginResultWithSkopeoCopy.plugin.dockerImageId,
    "6d5fcfe5ff170471fcc3c8b47631d6d71202a1fd44cf3c147e50c8de21cf0648",
    "image ID identified correctly",
  );
  t.equals(
    pluginResultWithSkopeoCopy.plugin.packageManager,
    "linux",
    "linux is the hackish package manager when nothing else is found",
  );
  t.same(depTree.dependencies, {}, "no known packages found");
  t.equals(
    depTree.packageFormatVersion,
    "linux:0.0.1",
    "the version of the linux package manager is 0.0.1",
  );
  t.deepEquals(
    depTree.targetOS,
    { name: "unknown", version: "0.0", prettyName: "" },
    "operating system for scratch image is unknown",
  );
  t.same(depTree.version, "1.31.1", "Version matches");
});

test("static scanning NGINX with dockerfile analysis matches expected values", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "nginx:latest";
  const dockerfilePath = path.join(
    __dirname,
    "../fixtures/dockerfiles/library/nginx/Dockerfile",
  );
  const pluginOptionsWithDockerSave = {
    staticAnalysisOptions: {
      imagePath: getFixture("docker-save/nginx.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResultStatic = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfilePath,
    pluginOptionsWithDockerSave,
  );

  const results = pluginResultStatic.scannedProjects;
  // implicitly identifying as osScanResult by existence of `docker` property
  const osScanResult = results.find((res) => "docker" in res.depTree);
  t.ok(osScanResult !== undefined, "found OS scan results");
  if (osScanResult === undefined) {
    throw new Error(
      "stop the test from proceeding because type safety was broken",
    );
  }
  const depTree = osScanResult.depTree as DepTree; // this is okay because we asserted `docker` is present
  const dockerResult = depTree.docker;

  t.equals(
    dockerResult.baseImage,
    "debian:stretch-slim",
    "base image matches expected",
  );

  t.ok(
    "apt-transport-https" in dockerResult.dockerfilePackages,
    "found apt-transport-https in dockerfile packages",
  );
  t.ok(
    "ca-certificates" in dockerResult.dockerfilePackages,
    "found ca-certificates in dockerfile packages",
  );
  t.ok(
    "gettext-base" in dockerResult.dockerfilePackages,
    "found gettext-base in dockerfile packages",
  );
  t.ok(
    "gnupg1" in dockerResult.dockerfilePackages,
    "found gnupg1 in dockerfile packages",
  );
});
