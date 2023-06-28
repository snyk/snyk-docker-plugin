import * as plugin from "../../lib";
import { ImageName } from "../../lib/extractor/image";
import { getFixture } from "../util";

it("provides imageName fact with digests and imageNameAndTag scan options", async () => {
  const fixturePath = getFixture([
    "/docker-archives",
    "skopeo-copy/busybox.tar",
  ]);
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResultWithDockerSave = await plugin.scan({
    path: imagePath,
    imageNameAndTag: "busybox:stable",
    digests: {
      manifest:
        "sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
      index:
        "sha256:bde251f3026301ad8f8d55f59bc09efefb9307148d3c82e4c89322e182718362",
    },
  });

  const imageName: ImageName =
    pluginResultWithDockerSave.scanResults[0].facts.find(
      (fact) => fact.type === "imageNames",
    )!.data;
  expect(imageName.names).toHaveLength(3);
  expect(imageName.names).toEqual(
    expect.arrayContaining([
      "busybox:stable",
      "busybox@sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
      "busybox@sha256:bde251f3026301ad8f8d55f59bc09efefb9307148d3c82e4c89322e182718362",
    ]),
  );
});

it("provides imageName fact with imageNameAndDigest and imageNameAndTag scan options", async () => {
  const fixturePath = getFixture([
    "/docker-archives",
    "skopeo-copy/busybox.tar",
  ]);
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResultWithDockerSave = await plugin.scan({
    path: imagePath,
    imageNameAndTag: "busybox:stable",
    imageNameAndDigest:
      "busybox@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
  });

  const imageName: ImageName =
    pluginResultWithDockerSave.scanResults[0].facts.find(
      (fact) => fact.type === "imageNames",
    )!.data;
  expect(imageName.names).toHaveLength(2);
  expect(imageName.names).toEqual(
    expect.arrayContaining([
      "busybox:stable",
      "busybox@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
    ]),
  );
});
