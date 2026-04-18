import { DepGraph } from "@snyk/dep-graph";
import * as plugin from "../../lib";
import * as subProcess from "../../lib/sub-process";
import { getFixture } from "../util";

describe("plugin", () => {
  describe("image is scanned when no image type is specified", () => {
    it("docker image.tar is scanned successfully when image type is not specified", async () => {
      const fixturePath = getFixture([
        "../fixtures/docker-archives",
        "alpine-arm64.tar",
      ]);
      const imagePath = `${fixturePath}`;

      const pluginResult = await plugin.scan({
        path: imagePath,
      });
      const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    });

    it("kaniko image.tar is scanned successfully when image type is not specified", async () => {
      const fixturePath = getFixture([
        "../fixtures/kaniko-archives",
        "kaniko-busybox.tar",
      ]);
      const imagePath = `${fixturePath}`;

      const pluginResult = await plugin.scan({
        path: imagePath,
      });
      const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    });
    it("oci image.tar is scanned successfully when image type is not specified", async () => {
      const fixturePath = getFixture([
        "../fixtures/docker-oci-archives",
        "busybox.amd64.tar",
      ]);
      const imagePath = `${fixturePath}`;

      const pluginResult = await plugin.scan({
        path: imagePath,
      });
      const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    });

    it("fails to extract the archive when the archive type is not supported", async () => {
      const fixturePath = getFixture([
        "../fixtures/docker-oci-archives",
        "unsupported-image.tar",
      ]);
      const imagePath = `${fixturePath}`;

      await expect(
        plugin.scan({
          path: imagePath,
        }),
      ).rejects.toThrow(
        "Unsupported archive type. Please use a Docker archive, OCI image layout, or Kaniko-compatible tarball.",
      );
    });
  });

  describe("docker-archive image type throws on bad files", () => {
    test("throws when a file does not exists", async () => {
      const path = "docker-archive:missing-path";

      const result = plugin.scan({
        path,
      });

      await expect(result).rejects.toThrow(
        "The provided archive path does not exist on the filesystem",
      );
    });

    test("throws when the provided path is a directory", async () => {
      const path = "docker-archive:/tmp";

      const result = plugin.scan({
        path,
      });

      await expect(result).rejects.toThrow(
        "The provided archive path is not a file",
      );
    });
  });

  test("image pulled by tag has version set", async () => {
    const imageNameAndTag = `nginx:1.19.0`;

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    //  image name matches
    expect(depGraph.rootPkg.name).toEqual("docker-image|nginx");
    //  version must not be empty
    expect(depGraph.rootPkg.version).toEqual("1.19.0");
  });

  describe("when scanning a locally loaded image", () => {
    const imageName = "busybox";
    const imageTag = "latest";
    const imageNameWithTag = `${imageName}:${imageTag}`;

    beforeAll(async () => {
      const fixturePath = getFixture([
        "../fixtures/docker-archives",
        "skopeo-copy/busybox.tar",
      ]);
      await subProcess.execute("docker", ["load", "--input", fixturePath]);
    }, 10000); // 10s timeout for loading image

    afterAll(async () => {
      await subProcess.execute("docker", ["rmi", imageNameWithTag]);
    });

    test("should successfully scan a local image loaded from a tar archive", async () => {
      const pluginResult = await plugin.scan({ path: imageNameWithTag });
      const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

      expect(depGraph.rootPkg.name).toEqual(`docker-image|${imageName}`);
      expect(depGraph.rootPkg.version).toEqual(imageTag);
      expect(pluginResult.scanResults[0].identity.type).toEqual("linux");
    });
  });

  test("static scan for Identifier type image (nginx:1.19.0)", async () => {
    // This digest resolves to the `1.19.0` tag. We're using the digest to guarantee we always get the correct
    // image, no matter on which platform this test is run on.
    const imageNameAndDigest = `nginx@sha256:0efad4d09a419dc6d574c3c3baacb804a530acd61d5eba72cb1f14e1f5ac0c8f`;

    const pluginResult = await plugin.scan({
      path: imageNameAndDigest,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    //  image name matches
    expect(depGraph.rootPkg.name).toEqual("docker-image|nginx");
    //  image has no version set because we pull by digest
    expect(depGraph.rootPkg.version).toBeUndefined();

    const imageId: string = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;

    //  the image ID matches
    expect(imageId).toEqual(
      "sha256:2622e6cca7ebbb6e310743abce3fc47335393e79171b9d76ba9d4f446ce7b163",
    );
    //  correct package manager detected
    expect(pluginResult.scanResults[0].identity.type).toEqual("deb");

    //  contains some expected dependency
    expect(
      depGraph.getDepPkgs().find((dep) => dep.name === "nginx"),
    ).toBeTruthy();

    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;

    //  layers are read correctly
    expect(imageLayers).toEqual([
      "sha256:8559a31e96f442f2c7b6da49d6c84705f98a39d8be10b3f5f14821d0ee8417df",
      "sha256:8d69e59170f7dac013ef436408ed9ddc688dd9ad3bc030bd868add55a77e25f8",
      "sha256:3f9f1ec1d262b2889a5fc19bf295f48346dbd8238e22f3eb3dd8a907ca002372",
      "sha256:d1f5ff4f210df5d5f6bf48438d33ba0d086c4e08a803acf22292ccd4ede92bd2",
      "sha256:1e22bfa8652e0db3a316e2c946ea048b60560630d4faa58405da4c5fcdb3ff07",
    ]);

    //  correct platform detected
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "linux/amd64",
    );
  });
});
