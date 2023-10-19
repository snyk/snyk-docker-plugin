import { DepGraph } from "@snyk/dep-graph";
import * as plugin from "../../lib";

describe("plugin", () => {
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
      "29a4ff5c2250ab72c60545ba67bd67d87daa05e4abd186e7d488d921287c893b/layer.tar",
      "bd0f0d2dba229cb9005123b54a646fe612882343c06b68c4722f221fdc597d82/layer.tar",
      "5a88377adcb6f00f0388d45a929fe1159916d7c9e733db78d6defb3fcd325a68/layer.tar",
      "94f68a38cdeff495ef63de6533b7d7486312ff7bc184120a620ad738536f548d/layer.tar",
      "44fc3f4af0d0f3587192b742d77b7c1c85cfd230bfb5474f6e1619da7962e3e3/layer.tar",
    ]);

    //  correct platform detected
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "linux/amd64",
    );
  });
});
