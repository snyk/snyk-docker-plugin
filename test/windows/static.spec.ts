import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import { DockerFileAnalysis } from "../../lib";

import * as plugin from "../../lib";

describe("static", () => {
  const getFixture = (fixturePath: string) =>
    path.join(__dirname, "../fixtures/docker-archives", fixturePath);

  afterEach(() => {
    jest.resetAllMocks();
  });

  test("static analysis builds the expected response", async () => {
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

    //  Test the skopeo-copy result.
    //    Has the expected result properties
    expect(
      "scanResults" in pluginResultWithSkopeoCopy &&
        Array.isArray(pluginResultWithSkopeoCopy.scanResults) &&
        pluginResultWithSkopeoCopy.scanResults.length === 1,
    ).toBeTruthy();

    const skopeoCopyDepGraph: DepGraph =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    //    Version is missing
    expect(skopeoCopyDepGraph.rootPkg.version).toBeUndefined();

    const skopeoCopyImageId: string =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "imageId",
      )!.data;

    //    The image ID matches
    expect(skopeoCopyImageId).toEqual(
      "sha256:ab56bba91343aafcdd94b7a44b42e12f32719b9a2b8579e93017c1280f48e8f3",
    );

    //    Correct package manager detected
    expect(pluginResultWithSkopeoCopy.scanResults[0].identity.type).toEqual(
      "deb",
    );

    const skopeoCopyImageLayers: string[] =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "imageLayers",
      )!.data;

    //    Layers are read correctly
    expect(skopeoCopyImageLayers).toEqual([
      "ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9.tar",
    ]);

    //    Contains some expected dependency
    expect(
      skopeoCopyDepGraph.getDepPkgs().find((dep) => dep.name === "adduser"),
    ).toBeTruthy();

    // Test the docker-save result.
    const dockerSaveImageLayers: string[] =
      pluginResultWithDockerSave.scanResults[0].facts.find(
        (fact) => fact.type === "imageLayers",
      )!.data;

    //    Layers are read correctly
    expect(dockerSaveImageLayers).toEqual([
      path.normalize(
        "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
      ),
    ]);

    const dockerSaveDepGraph: DepGraph =
      pluginResultWithDockerSave.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    //    The plugin scans both skopeo-copy and docker-save archives the same way
    expect(skopeoCopyDepGraph.getDepPkgs()).toStrictEqual(
      dockerSaveDepGraph.getDepPkgs(),
    );

    const compressedSkopeoCopyDepGraph: DepGraph =
      pluginResultWithCompressedSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    //    The plugin scans both skopeo-copy and docker-save archives the same way
    expect(compressedSkopeoCopyDepGraph.getDepPkgs()).toStrictEqual(
      dockerSaveDepGraph.getDepPkgs(),
    );

    //    Platform is returned with the result same way
    expect(
      pluginResultWithSkopeoCopy.scanResults[0].identity.args?.platform,
    ).toEqual(
      pluginResultWithDockerSave.scanResults[0].identity.args?.platform,
    );
  });

  test("static analysis provides hashes for key binaries", async () => {
    const pluginResultWithSkopeoCopy = await plugin.scan({
      path: `docker-archive:${getFixture("skopeo-copy/nodes-fake-multi.tar")}`,
    });

    const keyBinariesHashes: string[] =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "keyBinariesHashes",
      )!.data;

    //  found four key binaries
    expect(keyBinariesHashes.length).toEqual(4);

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
    const pluginResult = await plugin.scan({
      path: `docker-archive:${getFixture("docker-save/openjdk.tar")}`,
    });

    const keyBinariesHashes: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "keyBinariesHashes",
    )!.data;

    //  found one openjdk key binary
    expect(keyBinariesHashes.length).toEqual(1);

    const expectedHashes = [
      "004182a1acb5aad313f4554cbafe474a9bdc143260576ac3fa4ab388c3f40476",
    ];

    //  all key binaries match hashes
    expect(keyBinariesHashes).toEqual(expectedHashes);
  });

  test("static analysis works for scratch images", async () => {
    const pluginResultWithSkopeoCopy = await plugin.scan({
      path: `docker-archive:${getFixture("skopeo-copy/busybox.tar")}`,
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

    const imageLayers: string =
      pluginResultWithSkopeoCopy.scanResults[0].facts.find(
        (fact) => fact.type === "imageLayers",
      )!.data;

    //  image layers match
    expect(imageLayers).toEqual([
      "195be5f8be1df6709dafbba7ce48f2eee785ab7775b88e0c115d8205407265c5.tar",
    ]);

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

    //  version is not found
    expect(depGraph.rootPkg.version).toBeUndefined();

    //  platform is returned with the result same way
    expect(
      pluginResultWithSkopeoCopy.scanResults[0].identity.args?.platform,
    ).toEqual("linux/amd64");
  });

  test("static scanning NGINX with dockerfile analysis matches expected values", async () => {
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
});
