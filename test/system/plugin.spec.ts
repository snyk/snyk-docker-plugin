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
      "sha256:13cb14c2acd34e45446a50af25cb05095a17624678dbafbcc9e26086547c1d74",
      "sha256:d4cf327d8ef50eb2e31b646f17217a3baf455391bfd59bce47df50c770ff8c07",
      "sha256:7c7d7f4461826dd22f9234a81f9bed9c0bdb0b70b3ce66228bfc87418a9b8313",
      "sha256:9040af41bb6677b114134de15ddeb10b070eb1f940dbbe277574ee154d89f6b9",
      "sha256:f978b9ed3f26a49b55cf4849e4cadb29335be45a633cbe95a2f4e445e70086bf",
    ]);

    //  correct platform detected
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "linux/amd64",
    );
  });
});
