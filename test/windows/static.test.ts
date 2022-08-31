import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { DockerFileAnalysis } from "../../lib/dockerfile";

const getFixture = (fixturePath) =>
  path.join(__dirname, "../fixtures/docker-archives", fixturePath);

test("static analysis builds the expected response", async (t) => {
  const pluginResultWithSkopeoCopy = await plugin.scan({
    path: `docker-archive:${getFixture("skopeo-copy/nginx.tar")}`,
  });

  const pluginResultWithCompressedSkopeoCopy = await plugin.scan({
    path: `docker-archive:${getFixture(
      "skopeo-copy/nginx-compressed-layers.tar",
    )}`,
  });

  const pluginResultWithDockerSave = await plugin.scan({
    path: `docker-archive:${getFixture("docker-save/nginx.tar")}`,
  });

  // Test the skopeo-copy result.
  t.ok(
    "scanResults" in pluginResultWithSkopeoCopy &&
      Array.isArray(pluginResultWithSkopeoCopy.scanResults) &&
      pluginResultWithSkopeoCopy.scanResults.length === 1,
    "Has the expected result properties",
  );

  const skopeoCopyDepGraph: DepGraph =
    pluginResultWithSkopeoCopy.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
  t.same(skopeoCopyDepGraph.rootPkg.version, undefined, "Version is missing");

  const skopeoCopyImageId: string =
    pluginResultWithSkopeoCopy.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;
  t.same(
    skopeoCopyImageId,
    "sha256:ab56bba91343aafcdd94b7a44b42e12f32719b9a2b8579e93017c1280f48e8f3",
    "The image ID matches",
  );
  t.same(
    pluginResultWithSkopeoCopy.scanResults[0].identity.type,
    "deb",
    "Correct package manager detected",
  );

  const skopeoCopyImageLayers: string[] =
    pluginResultWithSkopeoCopy.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
  t.deepEqual(
    skopeoCopyImageLayers,
    ["ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9.tar"],
    "Layers are read correctly",
  );
  t.ok(
    skopeoCopyDepGraph.getDepPkgs().find((dep) => dep.name === "adduser"),
    "Contains some expected dependency",
  );

  // Test the docker-save result.
  const dockerSaveImageLayers: string[] =
    pluginResultWithDockerSave.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
  t.deepEqual(
    dockerSaveImageLayers,
    [
      path.normalize(
        "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
      ),
    ],
    "Layers are read correctly",
  );

  const dockerSaveDepGraph: DepGraph =
    pluginResultWithDockerSave.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
  t.deepEqual(
    skopeoCopyDepGraph.getDepPkgs(),
    dockerSaveDepGraph.getDepPkgs(),
    "The plugin scans both skopeo-copy and docker-save archives the same way",
  );

  const compressedSkopeoCopyDepGraph: DepGraph =
    pluginResultWithCompressedSkopeoCopy.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
  t.deepEqual(
    compressedSkopeoCopyDepGraph.getDepPkgs(),
    dockerSaveDepGraph.getDepPkgs(),
    "The plugin scans both skopeo-copy and docker-save archives the same way",
  );

  t.equal(
    pluginResultWithSkopeoCopy.scanResults[0].identity.args?.platform,
    pluginResultWithDockerSave.scanResults[0].identity.args?.platform,
    "Platform is returned with the result same way",
  );
});

test("static analysis provides hashes for key binaries", async (t) => {
  const pluginResultWithSkopeoCopy = await plugin.scan({
    path: `docker-archive:${getFixture("skopeo-copy/nodes-fake-multi.tar")}`,
  });

  const keyBinariesHashes: string[] =
    pluginResultWithSkopeoCopy.scanResults[0].facts.find(
      (fact) => fact.type === "keyBinariesHashes",
    )!.data;
  t.equals(keyBinariesHashes.length, 4, "found four key binaries");
  const expectedHashes = [
    "f20f16782d8c442142560d1dad09561161fb495179751db200d9db6caf6ad832",
    "c7f4fefb1e2994b8ac23134ea9c2b7aa8b2d088b8863fa33012ca7b8824e1bed",
    "0198b003dfe9fff4ee28ca7d75893bff7375dedd1a969c781771a4b34443fb33",
    "62f8defe3fe085af9b6e48f85ffb90a863c44d53b9c3f4f237b04c232f350083",
  ];
  t.deepEqual(
    keyBinariesHashes.sort(),
    expectedHashes.sort(),
    "all key binaries match hashes",
  );
});

test("static analysis provides hashes for found openjdk binaries", async (t) => {
  const pluginResult = await plugin.scan({
    path: `docker-archive:${getFixture("docker-save/openjdk.tar")}`,
  });

  const keyBinariesHashes: string[] = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "keyBinariesHashes",
  )!.data;
  t.equals(keyBinariesHashes.length, 1, "found one openjdk key binary");
  const expectedHashes = [
    "004182a1acb5aad313f4554cbafe474a9bdc143260576ac3fa4ab388c3f40476",
  ];
  t.deepEqual(
    keyBinariesHashes,
    expectedHashes,
    "all key binaries match hashes",
  );
});

test("static analysis works for scratch images", async (t) => {
  const pluginResultWithSkopeoCopy = await plugin.scan({
    path: `docker-archive:${getFixture("skopeo-copy/busybox.tar")}`,
  });

  const depGraph: DepGraph =
    pluginResultWithSkopeoCopy.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
  const imageId: string = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  t.equals(
    imageId,
    "sha256:6d5fcfe5ff170471fcc3c8b47631d6d71202a1fd44cf3c147e50c8de21cf0648",
    "image ID identified correctly",
  );
  const imageLayers: string =
    pluginResultWithSkopeoCopy.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
  t.deepEquals(
    imageLayers,
    ["195be5f8be1df6709dafbba7ce48f2eee785ab7775b88e0c115d8205407265c5.tar"],
    "image layers match",
  );
  t.equals(
    pluginResultWithSkopeoCopy.scanResults[0].identity.type,
    "linux",
    "linux is the hackish package manager when nothing else is found",
  );
  t.same(depGraph.getDepPkgs(), [], "no known packages found");
  t.deepEquals(
    depGraph.pkgManager.repositories,
    [{ alias: "unknown:0.0" }],
    "operating system for scratch image is unknown",
  );
  t.same(depGraph.rootPkg.version, undefined, "Version is not found");
  t.equals(
    pluginResultWithSkopeoCopy.scanResults[0].identity.args?.platform,
    "linux/amd64",
    "Platform is returned with the result same way",
  );
});

test("static scanning NGINX with dockerfile analysis matches expected values", async (t) => {
  const dockerfilePath = path.join(
    __dirname,
    "../fixtures/dockerfiles/library/nginx/Dockerfile",
  );
  const pluginResultStatic = await plugin.scan({
    path: `docker-archive:${getFixture("docker-save/nginx.tar")}`,
    file: dockerfilePath,
  });

  const dockerfileAnalysis: DockerFileAnalysis =
    pluginResultStatic.scanResults[0].facts.find(
      (fact) => fact.type === "dockerfileAnalysis",
    )!.data;

  t.equals(
    dockerfileAnalysis.baseImage,
    "debian:stretch-slim",
    "base image matches expected",
  );

  t.ok(
    "apt-transport-https" in dockerfileAnalysis.dockerfilePackages,
    "found apt-transport-https in dockerfile packages",
  );
  t.ok(
    "ca-certificates" in dockerfileAnalysis.dockerfilePackages,
    "found ca-certificates in dockerfile packages",
  );
  t.ok(
    "gettext-base" in dockerfileAnalysis.dockerfilePackages,
    "found gettext-base in dockerfile packages",
  );
  t.ok(
    "gnupg1" in dockerfileAnalysis.dockerfilePackages,
    "found gnupg1 in dockerfile packages",
  );
});
