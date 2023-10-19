import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";

import * as plugin from "../../lib";
import { DockerFileAnalysis } from "../../lib/dockerfile/types";
import { ManifestFile } from "../../lib/types";

describe("static", () => {
  const getFixture = (fixturePath) =>
    path.join(__dirname, "../fixtures/docker-archives", fixturePath);

  test("omitting required options for static analysis", async () => {
    //  static analysis requires parameters
    await expect(plugin.scan(undefined)).rejects.toThrow(
      Error("No plugin options provided"),
    );
    //  static analysis requires parameters
    await expect(plugin.scan({})).rejects.toThrow(
      Error("No image identifier or path provided"),
    );
    //  static analysis rejects on having imagePath but missing imageType
    await expect(
      plugin.scan({ path: "/var/tmp/image.nonexistent" }),
    ).rejects.toThrow(undefined);
  });

  test("/etc/os-release links to /usr/lib/os-release", async () => {
    const fixturePath = getFixture("docker-save/nginx-os-release-link.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResultWithDockerSave = await plugin.scan({
      path: imagePath,
    });

    const depGraph: DepGraph =
      pluginResultWithDockerSave.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    expect(depGraph.pkgManager.repositories).toEqual([{ alias: "debian:10" }]);
  });

  test("static analysis provides hashes for key binaries", async () => {
    const fixturePath = getFixture("skopeo-copy/nodes-fake-multi.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResultWithSkopeoCopy = await plugin.scan({
      path: imagePath,
    });

    const keyBinariesHashes: string[] =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "keyBinariesHashes",
      )!.data;

    //  found four key binaries
    expect(keyBinariesHashes).toHaveLength(4);
    const expectedHashes = [
      "f20f16782d8c442142560d1dad09561161fb495179751db200d9db6caf6ad832",
      "c7f4fefb1e2994b8ac23134ea9c2b7aa8b2d088b8863fa33012ca7b8824e1bed",
      "0198b003dfe9fff4ee28ca7d75893bff7375dedd1a969c781771a4b34443fb33",
      "62f8defe3fe085af9b6e48f85ffb90a863c44d53b9c3f4f237b04c232f350083",
    ];

    //  all key binaries match hashes
    expect(keyBinariesHashes.sort()).toEqual(expectedHashes.sort());
  });

  test("static analysis provides hashes for found openjdk binaries", async () => {
    const fixturePath = getFixture("docker-save/openjdk.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imagePath,
    });

    const keyBinariesHashes: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "keyBinariesHashes",
    )!.data;

    //  found one openjdk key binary
    expect(keyBinariesHashes).toHaveLength(1);

    const expectedHashes = [
      "004182a1acb5aad313f4554cbafe474a9bdc143260576ac3fa4ab388c3f40476",
    ];

    //  all key binaries match hashes
    expect(keyBinariesHashes).toEqual(expectedHashes);
  });

  test("static analysis works for scratch images", async () => {
    const fixturePath = getFixture("skopeo-copy/busybox.tar");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResultWithSkopeoCopy = await plugin.scan({
      path: imagePath,
    });

    const depGraph: DepGraph =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    const imageId: string =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "imageId",
      )!.data;

    //  image ID identified correctly
    expect(imageId).toEqual(
      "sha256:6d5fcfe5ff170471fcc3c8b47631d6d71202a1fd44cf3c147e50c8de21cf0648",
    );

    //  linux is the hackish package manager when nothing else is found
    expect(pluginResultWithSkopeoCopy.scanResults[0].identity.type).toEqual(
      "linux",
    );
    //  no known packages found
    expect(depGraph.getDepPkgs()).toEqual([]);
    //  operating system for scratch image is unknown
    expect(depGraph.pkgManager.repositories).toEqual([
      { alias: "unknown:0.0" },
    ]);
    //  Version is missing
    expect(depGraph.rootPkg.version).toBeUndefined();
    //  Platform is returned with the result same way
    expect(
      pluginResultWithSkopeoCopy.scanResults[0].identity.args?.platform,
    ).toEqual("linux/amd64");
  });

  test("static analysis for distroless base-debian9", async () => {
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

    //  Distroless base image dependencies are correct
    expect(
      expectedDependencies.every(
        (expectedDep) =>
          depGraphDepPkgs.find(
            (depPkg) =>
              depPkg.name === expectedDep.name &&
              depPkg.version === expectedDep.version,
          ) !== undefined,
      ),
    ).toBeTruthy();

    //  recognised it's debian 9
    expect(depGraph.pkgManager.repositories).toEqual([{ alias: "debian:9" }]);
    //  Version matches
    expect(depGraph.rootPkg.version).toEqual(
      "70b8c7f2d41a844d310c23e0695388c916a364ed",
    );
  });

  test("manifest files are detected", async () => {
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
    expect(osDepsStatic).not.toBeUndefined();

    const manifestFiles: ManifestFile[] = osDepsStatic.facts.find(
      (fact) => fact.type === "imageManifestFiles",
    )!.data;

    //  found manifest files in static scan
    expect(manifestFiles).not.toBeUndefined();

    //  static scan finds one manifest file because it doesn't follow on symlinks
    expect(manifestFiles).toHaveLength(1);

    //  static scanned manifest files are held in a base64-encoded string
    //  match on some of the contents (the end of the file)
    expect(manifestFiles[0].contents).toMatch("kZWJpYW4ub3JnLyIK");
  });

  test("static scanning NGINX with dockerfile analysis matches expected values", async () => {
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

    const dockerfileAnalysis: DockerFileAnalysis =
      pluginResultStatic.scanResults[0].facts.find(
        (fact) => fact.type === "dockerfileAnalysis",
      )!.data;

    //  base image matches expected
    expect(dockerfileAnalysis.baseImage).toEqual("debian:stretch-slim");

    //  found apt-transport-https in dockerfile packages
    expect(dockerfileAnalysis.dockerfilePackages).toHaveProperty(
      "apt-transport-https",
    );
    //  found ca-certificates in dockerfile packages
    expect(dockerfileAnalysis.dockerfilePackages).toHaveProperty(
      "ca-certificates",
    );
    //  found gettext-base in dockerfile packages
    expect(dockerfileAnalysis.dockerfilePackages).toHaveProperty(
      "gettext-base",
    );
    //  found gnupg1 in dockerfile packages
    expect(dockerfileAnalysis.dockerfilePackages).toHaveProperty("gnupg1");
  });

  test("able to scan opensuse/leap images", async () => {
    const imgName = "opensuse/leap";
    // digest corresponds to tag 15.1, but makes the image platform-independent.
    const imgDigest =
      "@sha256:2288f0d5caec6a4b7f6b76d7a1ef6cf738f94c8f10941ea1840a365a61ed6219";
    const img = imgName + imgDigest;

    const pluginResult = await plugin.scan({
      path: img,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    //  returns rpm package manager
    expect(pluginResult.scanResults[0].identity.type).toEqual("rpm");
    //  expected root package name
    expect(depGraph.rootPkg.name).toEqual("docker-image|" + imgName);
    //  OS image detected
    expect(depGraph.pkgManager.repositories).toEqual([
      { alias: "opensuse-leap:15.1" },
    ]);
    //  expected number of direct deps
    expect(depGraph.getDepPkgs()).toHaveLength(125);
  });
});
