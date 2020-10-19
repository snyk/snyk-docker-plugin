import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { DockerFileAnalysis } from "../../lib/docker-file";

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

  const skopeoCopyDepGraph: DepGraph = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.same(skopeoCopyDepGraph.rootPkg.version, undefined, "Version is missing");

  const skopeoCopyImageId: string = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  t.same(
    skopeoCopyImageId,
    "ab56bba91343aafcdd94b7a44b42e12f32719b9a2b8579e93017c1280f48e8f3",
    "The image ID matches",
  );
  t.same(
    pluginResultWithSkopeoCopy.scanResults[0].identity.type,
    "deb",
    "Correct package manager detected",
  );

  const skopeoCopyImageLayers: string[] = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
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

  const skopeoCopyRootFs: string[] = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "rootFs",
  )!.data;
  t.deepEqual(
    skopeoCopyRootFs,
    [
      "sha256:2db44bce66cde56fca25aeeb7d09dc924b748e3adfe58c9cc3eb2bd2f68a1b68",
      "sha256:16d1b1dd2a23a7a79426299fde8be361194007dfebb3438f96735755283becf8",
      "sha256:ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9",
    ],
    "Base image layers are read correctly",
  );

  // Test the docker-save result.
  const dockerSaveImageLayers: string[] = pluginResultWithDockerSave.scanResults[0].facts.find(
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

  const dockerSaveDepGraph: DepGraph = pluginResultWithDockerSave.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.deepEqual(
    skopeoCopyDepGraph.getDepPkgs(),
    dockerSaveDepGraph.getDepPkgs(),
    "The plugin scans both skopeo-copy and docker-save archives the same way",
  );

  const dockerSaveRootFs: string[] = pluginResultWithDockerSave.scanResults[0].facts.find(
    (fact) => fact.type === "rootFs",
  )!.data;
  t.deepEqual(
    dockerSaveRootFs,
    [
      "sha256:1c95c77433e8d7bf0f519c9d8c9ca967e2603f0defbf379130d9a841cca2e28e",
      "sha256:002a63507c1caa5cc0e1af10e5b888f6ba20d06275e989a452581d789a48948e",
      "sha256:12fdf55172df870a613a79c4757006c5b28e66a8621c3e26916678378568f078",
    ],
    "Base image layers are read correctly",
  );

  const compressedSkopeoCopyDepGraph: DepGraph = pluginResultWithCompressedSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.deepEqual(
    compressedSkopeoCopyDepGraph.getDepPkgs(),
    dockerSaveDepGraph.getDepPkgs(),
    "The plugin scans both skopeo-copy and docker-save archives the same way",
  );

  const compressedSkopeoCopyRootFs: string[] = pluginResultWithCompressedSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "rootFs",
  )!.data;
  t.deepEqual(
    compressedSkopeoCopyRootFs,
    [
      "sha256:2db44bce66cde56fca25aeeb7d09dc924b748e3adfe58c9cc3eb2bd2f68a1b68",
      "sha256:16d1b1dd2a23a7a79426299fde8be361194007dfebb3438f96735755283becf8",
      "sha256:ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9",
    ],
    "Base image layers are read correctly",
  );

  t.equal(
    pluginResultWithSkopeoCopy.scanResults[0].identity.args?.platform,
    pluginResultWithDockerSave.scanResults[0].identity.args?.platform,
    "Platform is returned with the result same way",
  );
});

test("omitting required options for static analysis", async (t) => {
  await t.rejects(
    plugin.scan(undefined),
    Error("No plugin options provided"),
    "static analysis requires parameters",
  );

  await t.rejects(
    plugin.scan({}),
    Error("No image identifier or path provided"),
    "static analysis requires parameters",
  );

  await t.rejects(
    plugin.scan({ path: "/var/tmp/image.nonexistent" }),
    undefined,
    "static analysis rejects on having imagePath but missing imageType",
  );
});

test("/etc/os-release links to /usr/lib/os-release", async (t) => {
  const fixturePath = getFixture("docker-save/nginx-os-release-link.tar");
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResultWithDockerSave = await plugin.scan({
    path: imagePath,
  });

  const depGraph: DepGraph = pluginResultWithDockerSave.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;

  t.deepEqual(depGraph.pkgManager.repositories, [{ alias: "debian:10" }]);
});

test("static analysis provides hashes for key binaries", async (t) => {
  const fixturePath = getFixture("skopeo-copy/nodes-fake-multi.tar");
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResultWithSkopeoCopy = await plugin.scan({
    path: imagePath,
  });

  const keyBinariesHashes: string[] = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
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
  const fixturePath = getFixture("docker-save/openjdk.tar");
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResult = await plugin.scan({
    path: imagePath,
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
  const fixturePath = getFixture("skopeo-copy/busybox.tar");
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResultWithSkopeoCopy = await plugin.scan({
    path: imagePath,
  });

  const depGraph: DepGraph = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const imageId: string = pluginResultWithSkopeoCopy.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;

  t.equals(
    imageId,
    "6d5fcfe5ff170471fcc3c8b47631d6d71202a1fd44cf3c147e50c8de21cf0648",
    "image ID identified correctly",
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
  t.same(depGraph.rootPkg.version, undefined, "Version is missing");
  t.equals(
    pluginResultWithSkopeoCopy.scanResults[0].identity.args?.platform,
    "linux/amd64",
    "Platform is returned with the result same way",
  );
});

test("static analysis for distroless base-debian9", async (t) => {
  // 70b8c7f2d41a844d310c23e0695388c916a364ed was "latest" at the time of writing
  const imageNameAndTag =
    "gcr.io/distroless/base-debian9:70b8c7f2d41a844d310c23e0695388c916a364ed";

  const pluginResult = await plugin.scan({
    path: imageNameAndTag,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;

  const expectedDependencies = [
    { name: "glibc/libc6", version: "2.24-11+deb9u4" },
    { name: "openssl/libssl1.1", version: "1.1.0l-1~deb9u1" },
    { name: "openssl", version: "1.1.0l-1~deb9u1" },
    { name: "base-files", version: "9.9+deb9u12" },
    { name: "netbase", version: "5.4" },
    { name: "tzdata", version: "2019c-0+deb9u1" },
  ];

  const depGraphDepPkgs = depGraph.getDepPkgs();
  t.ok(
    expectedDependencies.every(
      (expectedDep) =>
        depGraphDepPkgs.find(
          (depPkg) =>
            depPkg.name === expectedDep.name &&
            depPkg.version === expectedDep.version,
        ) !== undefined,
    ),
    "Distroless base image dependencies are correct",
  );

  t.deepEquals(
    depGraph.pkgManager.repositories,
    [{ alias: "debian:9" }],
    "recognised it's debian 9",
  );
  t.same(
    depGraph.rootPkg.version,
    "70b8c7f2d41a844d310c23e0695388c916a364ed",
    "Version matches",
  );
});

test("static analysis for distroless base-debian10", async (t) => {
  // 70b8c7f2d41a844d310c23e0695388c916a364ed was "latest" at the time of writing
  const imageNameAndTag =
    "gcr.io/distroless/base-debian10:70b8c7f2d41a844d310c23e0695388c916a364ed";
  const pluginResult = await plugin.scan({ path: imageNameAndTag });

  const expectedDependencies = [
    { name: "glibc/libc6", version: "2.28-10" },
    { name: "openssl/libssl1.1", version: "1.1.1d-0+deb10u2" },
    { name: "openssl", version: "1.1.1d-0+deb10u2" },
    { name: "base-files", version: "10.3+deb10u3" },
    { name: "netbase", version: "5.6" },
    { name: "tzdata", version: "2019c-0+deb10u1" },
  ];

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;

  const depGraphDepPkgs = depGraph.getDepPkgs();
  t.ok(
    expectedDependencies.every(
      (expectedDep) =>
        depGraphDepPkgs.find(
          (depPkg) =>
            depPkg.name === expectedDep.name &&
            depPkg.version === expectedDep.version,
        ) !== undefined,
    ),
    "Distroless base image dependencies are correct",
  );

  t.deepEquals(
    depGraph.pkgManager.repositories,
    [{ alias: "debian:10" }],
    "recognised it's debian 10",
  );
  t.same(
    depGraph.rootPkg.version,
    "70b8c7f2d41a844d310c23e0695388c916a364ed",
    "Version matches",
  );
});

test("manifest files are detected", async (t) => {
  const imageNameAndTag = "debian:10";
  const manifestGlobs = [
    "/etc/redhat-release*",
    "/etc/foo",
    "/nonexist/bar",
    "/etc/alpine-release",
    "**/os-release",
  ];
  const manifestExcludeGlobs = ["**/node_modules/**"];

  const pluginResultStatic = await plugin.scan({
    path: imageNameAndTag,
    globsToFind: {
      include: manifestGlobs,
      exclude: manifestExcludeGlobs,
    },
  });

  const osDepsStatic = pluginResultStatic.scanResults[0];
  t.ok(osDepsStatic !== undefined);

  const manifestFiles = pluginResultStatic.manifestFiles;
  t.ok(manifestFiles !== undefined, "found manifest files in static scan");
  t.equals(
    manifestFiles?.length,
    1,
    "static scan finds one manifest file because it doesn't follow on symlinks",
  );
  t.true(
    Buffer.isBuffer(manifestFiles?.[0].contents),
    "static scanned manifest files are held in buffer",
  );
});

test("static scanning NGINX with dockerfile analysis matches expected values", async (t) => {
  const dockerfilePath = path.join(
    __dirname,
    "../fixtures/dockerfiles/library/nginx/Dockerfile",
  );
  const fixturePath = getFixture("docker-save/nginx.tar");
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResultStatic = await plugin.scan({
    path: imagePath,
    file: dockerfilePath,
  });

  const dockerfileAnalysis: DockerFileAnalysis = pluginResultStatic.scanResults[0].facts.find(
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

test("static analysis for arm based image", async (t) => {
  const imageNameAndTag = "arm64v8/nginx:1.19.2-alpine";
  const pluginResult = await plugin.scan({
    path: imageNameAndTag,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;

  t.ok(depGraph.getDepPkgs().length, "packages have dependencies");
  t.equal(
    pluginResult.scanResults[0].target.image,
    "docker-image|arm64v8/nginx",
    "image exists in the scan result target",
  );
  t.deepEqual(
    depGraph.pkgManager.repositories,
    [{ alias: "alpine:3.12.0" }],
    "found os scan result",
  );
  t.equal(
    pluginResult.scanResults[0].identity.args?.platform,
    "linux/arm64",
    "Platform is returned with the result same way",
  );
});

test("able to scan SUSE images", async (t) => {
  const imgName = "registry.suse.com/suse/sle15";
  const imgTag = "15.1";
  const img = imgName + ":" + imgTag;

  const pluginResult = await plugin.scan({
    path: img,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;

  t.equal(
    pluginResult.scanResults[0].identity.type,
    "rpm",
    "returns rpm package manager",
  );

  t.same(
    depGraph.rootPkg.name,
    "docker-image|" + imgName,
    "expected root package name",
  );
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "sles:15.1" }],
    "OS image detected",
  );

  t.equal(depGraph.getDepPkgs().length, 121, "expected number of direct deps");
});

test("able to scan opensuse/leap images", async (t) => {
  const imgName = "opensuse/leap";
  const imgTag = "15.1";
  const img = imgName + ":" + imgTag;

  const pluginResult = await plugin.scan({
    path: img,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;

  t.equal(
    pluginResult.scanResults[0].identity.type,
    "rpm",
    "returns rpm package manager",
  );

  t.same(
    depGraph.rootPkg.name,
    "docker-image|" + imgName,
    "expected root package name",
  );
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "opensuse-leap:15.1" }],
    "OS image detected",
  );

  t.equal(depGraph.getDepPkgs().length, 124, "expected number of direct deps");
});
