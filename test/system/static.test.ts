import * as os from "os";
import * as path from "path";
import sinon = require("sinon");
import { test } from "tap";

import * as plugin from "../../lib";
import { Docker } from "../../lib/docker";
import * as subProcess from "../../lib/sub-process";
import {
  DepTree,
  ImageType,
  PluginResponseStatic,
  ScannedProjectExtended,
  ScannedProjectManifestFiles,
  ScanType,
} from "../../lib/types";

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
      "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
    ],
    "Layers are read correctly",
  );

  t.deepEqual(
    pluginResultWithSkopeoCopy.scannedProjects[0].depTree.dependencies,
    pluginResultWithDockerSave.scannedProjects[0].depTree.dependencies,
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

  const depTree = pluginResultWithDockerSave.scannedProjects[0]
    .depTree as DepTree;
  t.deepEqual(depTree.targetOS, {
    name: "debian",
    version: "10",
    prettyName: "Debian GNU/Linux 10 (buster)",
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

test("static analysis for distroless base-debian9", async (t) => {
  // 70b8c7f2d41a844d310c23e0695388c916a364ed was "latest" at the time of writing
  const imageNameAndTag =
    "gcr.io/distroless/base-debian9:70b8c7f2d41a844d310c23e0695388c916a364ed";

  const dockerfile = undefined;
  const pluginOptions = {
    experimental: true,
  };

  const pluginResult = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptions,
  );

  const expectedDependencies = {
    "glibc/libc6": { name: "glibc/libc6", version: "2.24-11+deb9u4" },
    "openssl/libssl1.1": {
      name: "openssl/libssl1.1",
      version: "1.1.0l-1~deb9u1",
      dependencies: {
        "glibc/libc6": { name: "glibc/libc6", version: "2.24-11+deb9u4" },
      },
    },
    openssl: {
      name: "openssl",
      version: "1.1.0l-1~deb9u1",
      dependencies: {
        "glibc/libc6": { name: "glibc/libc6", version: "2.24-11+deb9u4" },
        "openssl/libssl1.1": {
          name: "openssl/libssl1.1",
          version: "1.1.0l-1~deb9u1",
        },
      },
    },
    "base-files": { name: "base-files", version: "9.9+deb9u12" },
    netbase: { name: "netbase", version: "5.4" },
    tzdata: { name: "tzdata", version: "2019c-0+deb9u1" },
  };

  const depTree = pluginResult.scannedProjects[0].depTree as DepTree;
  t.ok("dependencies" in depTree, "packages have dependencies");
  t.deepEquals(
    depTree.dependencies,
    expectedDependencies,
    "Distroless base image dependencies are correct",
  );

  t.ok("targetOS" in depTree, "OS discovered");
  t.deepEquals(
    depTree.targetOS,
    { name: "debian", version: "9", prettyName: "Distroless" },
    "recognised it's debian 9",
  );
  t.same(
    depTree.version,
    "70b8c7f2d41a844d310c23e0695388c916a364ed",
    "Version matches",
  );
});

test("static analysis for distroless base-debian10", async (t) => {
  // 70b8c7f2d41a844d310c23e0695388c916a364ed was "latest" at the time of writing
  const imageNameAndTag =
    "gcr.io/distroless/base-debian10:70b8c7f2d41a844d310c23e0695388c916a364ed";

  const dockerfile = undefined;
  const pluginOptions = {
    experimental: true,
  };

  const pluginResult = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptions,
  );

  const expectedDependencies = {
    "glibc/libc6": { name: "glibc/libc6", version: "2.28-10" },
    "openssl/libssl1.1": {
      name: "openssl/libssl1.1",
      version: "1.1.1d-0+deb10u2",
      dependencies: {
        "glibc/libc6": { name: "glibc/libc6", version: "2.28-10" },
      },
    },
    openssl: {
      name: "openssl",
      version: "1.1.1d-0+deb10u2",
      dependencies: {
        "glibc/libc6": { name: "glibc/libc6", version: "2.28-10" },
        "openssl/libssl1.1": {
          name: "openssl/libssl1.1",
          version: "1.1.1d-0+deb10u2",
        },
      },
    },
    "base-files": { name: "base-files", version: "10.3+deb10u3" },
    netbase: { name: "netbase", version: "5.6" },
    tzdata: { name: "tzdata", version: "2019c-0+deb10u1" },
  };

  const depTree = pluginResult.scannedProjects[0].depTree as DepTree;
  t.ok("dependencies" in depTree, "packages have dependencies");
  t.deepEquals(
    depTree.dependencies,
    expectedDependencies,
    "Distroless base image dependencies are correct",
  );

  t.ok("targetOS" in pluginResult.scannedProjects[0].depTree, "OS discovered");
  t.deepEquals(
    depTree.targetOS,
    { name: "debian", version: "10", prettyName: "Distroless" },
    "recognised it's debian 10",
  );
  t.same(
    depTree.version,
    "70b8c7f2d41a844d310c23e0695388c916a364ed",
    "Version matches",
  );
});

test("experimental static analysis for debian images", async (t) => {
  const dockerSaveStub = sinon.stub(Docker.prototype, "save").callThrough();

  t.teardown(() => {
    dockerSaveStub.restore();
  });

  const imageNameAndTag = "debian:10";
  const dockerfile = undefined;

  const pluginOptionsExperimental = {
    experimental: true,
  };
  const pluginResultExperimental = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptionsExperimental,
  );

  t.equal(
    dockerSaveStub.callCount,
    1,
    "non-static experimental flag saves the image",
  );

  // static scan doesn't handle creating the image archive yet
  const archivePath = path.join(os.tmpdir(), "debian-10.tar");
  await subProcess.execute("docker", [
    "save",
    imageNameAndTag,
    "-o",
    archivePath,
  ]);
  const pluginOptionsStatic = {
    staticAnalysisOptions: {
      imagePath: archivePath,
      imageType: ImageType.DockerArchive,
    },
  };
  const pluginResultStatic = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptionsStatic,
  );

  t.equals(
    JSON.stringify(
      pluginResultExperimental.scannedProjects[0].depTree.dependencies,
    ),
    JSON.stringify(pluginResultStatic.scannedProjects[0].depTree.dependencies),
    "identical dependencies for regular Debian images between experimental and static scans",
  );

  t.equal(
    dockerSaveStub.callCount,
    1,
    "static experimental flag does not save the image",
  );
  t.same(
    pluginResultStatic.scannedProjects[0].depTree.version,
    "10",
    "Version matches",
  );
});

test("static and dynamic scanning results are aligned", async (t) => {
  const imageNameAndTag = "debian:10";
  const dockerfile = undefined;
  const manifestGlobs = [
    "/etc/redhat-release*",
    "/etc/foo",
    "/nonexist/bar",
    "/etc/alpine-release",
    "**/os-release",
  ];
  const manifestExcludeGlobs = ["**/node_modules/**"];

  await subProcess.execute("docker", ["image", "pull", imageNameAndTag]);
  const pluginResultDynamic = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    { manifestGlobs, manifestExcludeGlobs },
  );

  // static scan doesn't handle creating the image archive yet
  const archivePath = path.join(os.tmpdir(), "debian-10.tar");
  await subProcess.execute("docker", [
    "save",
    imageNameAndTag,
    "-o",
    archivePath,
  ]);
  const pluginOptionsStatic = {
    staticAnalysisOptions: {
      imagePath: archivePath,
      imageType: ImageType.DockerArchive,
    },
    manifestGlobs,
    manifestExcludeGlobs,
  };
  const pluginResultStatic = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptionsStatic,
  );

  const osDepsDynamic = pluginResultDynamic.scannedProjects.find(
    (res) => res.packageManager === "deb",
  );
  const osDepsStatic = pluginResultStatic.scannedProjects.find(
    (res) => res.packageManager === "deb",
  );
  t.ok(osDepsStatic !== undefined);

  t.same(
    osDepsDynamic!.depTree.dependencies,
    osDepsStatic!.depTree.dependencies,
    "identical dependencies for regular Debian images between dynamic and static scans",
  );

  t.equals(
    pluginResultDynamic.plugin.dockerImageId,
    `sha256:${pluginResultStatic.plugin.dockerImageId}`, // TODO: how to handle that?
    "image IDs, which is actually the image digest, is kind of equal between scan types",
  );
  // TODO: imageLayers is completely different

  const manifestFilesDynamic = pluginResultDynamic.scannedProjects.find(
    (res) => {
      if (!("scanType" in res)) {
        return false;
      }
      const scannedProjectExtended = res as ScannedProjectExtended;
      return scannedProjectExtended.scanType === ScanType.ManifestFiles;
    },
  ) as ScannedProjectManifestFiles;

  const manifestFilesStatic = pluginResultStatic.scannedProjects.find((res) => {
    if (!("scanType" in res)) {
      return false;
    }
    const scannedProjectExtended = res as ScannedProjectExtended;
    return scannedProjectExtended.scanType === ScanType.ManifestFiles;
  }) as ScannedProjectManifestFiles;

  t.ok(
    manifestFilesStatic !== undefined,
    "found manifest files in static scan",
  );
  t.ok(
    manifestFilesDynamic !== undefined,
    "found manifest files in dynamic scan",
  );
  t.equals(
    manifestFilesStatic.data.length,
    1,
    "static scan finds one manifest file because it doesn't follow on symlinks",
  );
  t.equals(
    manifestFilesDynamic.data.length,
    2,
    "dynamic scan finds two manifest files beause it follows on symlinks",
  );
  t.same(
    manifestFilesDynamic.data[0].contents,
    manifestFilesDynamic.data[1].contents,
    "symbolic links generate the same content",
  );
  t.same(
    Buffer.from(manifestFilesStatic.data[0].contents).toString("base64"),
    manifestFilesDynamic.data[0].contents,
    "dynamic scanned manifest files are base64 encoded",
  );
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
