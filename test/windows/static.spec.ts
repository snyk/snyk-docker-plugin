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

    //    Layers are read correctly (rootFsLayers / DiffIDs)
    expect(skopeoCopyImageLayers).toEqual([
      "sha256:2db44bce66cde56fca25aeeb7d09dc924b748e3adfe58c9cc3eb2bd2f68a1b68",
      "sha256:16d1b1dd2a23a7a79426299fde8be361194007dfebb3438f96735755283becf8",
      "sha256:ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9",
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

    //    Layers are read correctly (rootFsLayers / DiffIDs)
    expect(dockerSaveImageLayers).toEqual([
      "sha256:1c95c77433e8d7bf0f519c9d8c9ca967e2603f0defbf379130d9a841cca2e28e",
      "sha256:002a63507c1caa5cc0e1af10e5b888f6ba20d06275e989a452581d789a48948e",
      "sha256:12fdf55172df870a613a79c4757006c5b28e66a8621c3e26916678378568f078",
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

    //  image layers match (rootFsLayers / DiffIDs)
    expect(imageLayers).toEqual([
      "sha256:195be5f8be1df6709dafbba7ce48f2eee785ab7775b88e0c115d8205407265c5",
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
