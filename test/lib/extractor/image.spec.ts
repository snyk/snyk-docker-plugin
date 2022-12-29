import { getImageNames, ImageName } from "../../../lib/extractor/image";

const imageCases = [
  ["nginx:latest", {}, "nginx", "latest", ["nginx:latest"]],
  [
    "nginx@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
    {},
    "nginx",
    undefined,
    [
      "nginx@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
    ],
  ],
  [
    "gcr.io/nginx:latest",
    {
      manifest:
        "sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
    },
    "gcr.io/nginx",
    "latest",
    [
      "gcr.io/nginx:latest",
      "gcr.io/nginx@sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
    ],
  ],
  [
    "gcr.io/nginx:latest",
    {
      manifest:
        "sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
      index:
        "sha256:bde251f3026301ad8f8d55f59bc09efefb9307148d3c82e4c89322e182718362",
    },
    "gcr.io/nginx",
    "latest",
    [
      "gcr.io/nginx:latest",
      "gcr.io/nginx@sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
      "gcr.io/nginx@sha256:bde251f3026301ad8f8d55f59bc09efefb9307148d3c82e4c89322e182718362",
    ],
  ],
];

describe("ImageName class can handle given inputs", () => {
  test.each(imageCases)(
    "given image %p, digests %p, expect name to be %p, tag to be %p and imageNames to be %p",
    (image, digest, expectedName, expectedTag, expectedImageNames) => {
      const imageName = new ImageName(image, digest);
      expect(imageName.name).toEqual(expectedName);
      expect(imageName.tag).toEqual(expectedTag);
      expect(imageName.getAllNames()).toEqual(expectedImageNames);
    },
  );

  test("ImageName class throws an error when empty target image was provided", () => {
    expect(() => new ImageName("")).toThrowError("image name is empty");
  });

  test("ImageName class throws an error when target image is invalid", () => {
    expect(() => new ImageName("gcr.io/nginx@sha:something")).toThrowError(
      "invalid image reference format",
    );
  });

  test("ImageDigest class throws an error when digest algorithm is not supported", () => {
    expect(
      () =>
        new ImageName("gcr.io/nginx:1.23.0", {
          manifest:
            "sha224:db669ef3c32e4de05d9a3b63e9cb8bc3225a37a2b7c366fb2792a411",
        }),
    ).toThrowError(
      expect.objectContaining({
        message: expect.stringContaining("unsupported digest algorithm"),
      }),
    );
  });
});

describe("getImageNames can handle given inputs", () => {
  test("getImageNames return an array with name and tag when only imageNameAndTag option was provided", () => {
    const names = getImageNames({ imageNameAndTag: "nginx:latest" }, undefined);
    expect(names).toEqual(["nginx:latest"]);
  });

  test("getImageNames return an array with two elements when only imageNameAndTag and imageNameAndDigest options were provided", () => {
    const names = getImageNames(
      {
        imageNameAndTag: "nginx:latest",
        imageNameAndDigest:
          "nginx@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
      },
      undefined,
    );
    expect(names).toEqual([
      "nginx:latest",
      "nginx@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
    ]);
  });

  test("getImageNames return an array with one elements when imageNameAndTag and imageNameAndDigest options are the same", () => {
    const names = getImageNames(
      {
        imageNameAndTag:
          "nginx@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
        imageNameAndDigest:
          "nginx@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
      },
      undefined,
    );
    expect(names).toEqual([
      "nginx@sha256:a29baa1d6820ccfc12f25dd9b4de24b998cab06826df2704fc8182e437147a5b",
    ]);
  });

  test("getImageNames return an array when an imageName instance was provided", () => {
    const image = "nginx:latest";
    const digest = {
      manifest:
        "sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
    };
    const imageName = new ImageName(image, digest);
    const names = getImageNames(undefined, imageName);
    expect(names).toEqual([
      "nginx:latest",
      "nginx@sha256:9604d5d228cf1ba638a767b0d879b600cf288c5aecd68c8b35e30911aadf0dab",
    ]);
  });
});
