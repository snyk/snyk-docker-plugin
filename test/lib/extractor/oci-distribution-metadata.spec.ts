import {
  constructOCIDisributionMetadata,
  OCIDistributionMetadata,
} from "../../../lib/extractor/oci-distribution-metadata";

describe("constructOCIDisributionMetadata should", () => {
  const testCases: Array<
    [
      string,
      {
        imageName: string;
        manifestDigest: string;
        indexDigest?: string;
      },
      OCIDistributionMetadata | undefined,
    ]
  > = [
    [
      "given minimal information produce a valid result",
      {
        imageName: "gcr.io/example/repo:test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      {
        imageTag: "test",
        indexDigest: undefined,
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        registryHost: "gcr.io",
        repository: "example/repo",
      },
    ],
    [
      "given an index digest include it in the result",
      {
        imageName: "gcr.io/example/repo:test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        indexDigest:
          "sha256:8e552c2054fbd598196e35e5d04d4ad3cc1913d49ac5f9ed7235993f442dd9c6",
      },
      {
        imageTag: "test",
        indexDigest:
          "sha256:8e552c2054fbd598196e35e5d04d4ad3cc1913d49ac5f9ed7235993f442dd9c6",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        registryHost: "gcr.io",
        repository: "example/repo",
      },
    ],
    [
      "given an image name with a digest imageTag is not included in the result",
      {
        imageName:
          "gcr.io/example/repo@sha256:8e552c2054fbd598196e35e5d04d4ad3cc1913d49ac5f9ed7235993f442dd9c6",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      {
        imageTag: undefined,
        indexDigest: undefined,
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        registryHost: "gcr.io",
        repository: "example/repo",
      },
    ],
    [
      "given an image name without a host include the default in the result",
      {
        imageName: "example/repo:test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      {
        imageTag: "test",
        indexDigest: undefined,
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        registryHost: "docker.io",
        repository: "example/repo",
      },
    ],
    [
      "given an image name without a namespace include the default repository in the result",
      {
        imageName: "repo:test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      {
        imageTag: "test",
        indexDigest: undefined,
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        registryHost: "docker.io",
        repository: "library/repo",
      },
    ],
    [
      "given an image name with host that is too long should return undefined",
      {
        // 255 is the maxmimum host length.
        imageName: "a".repeat(256) + ".io/repo:test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      undefined,
    ],
    [
      "given an image name with a namespace that is too long should return undefined",
      {
        // 2048 is the maxmimum repository length.
        imageName: "gcr.io/" + "a".repeat(2049) + ":test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      undefined,
    ],
    [
      "given an image name with an invalid host should return undefined",
      {
        imageName: "..io/repo:test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      undefined,
    ],
    [
      "given an image name with an invalid namespace should return undefined",
      {
        imageName: "gcr.io/re*&&po:test",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      undefined,
    ],
    [
      "given an image name with an invalid tag should return undefined",
      {
        imageName: "gcr.io/example/repo:__*image=",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      undefined,
    ],
    [
      "given an invalid manifest digest should return undefined",
      {
        imageName: "gcr.io/example/repo:test",
        manifestDigest: "sha256:abc",
      },
      undefined,
    ],
    [
      "given an invalid index digest should return undefined",
      {
        imageName: "gcr.io/example/repo:test",
        indexDigest: "sha256:abc",
        manifestDigest:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      undefined,
    ],
  ];

  it.each(testCases)("%p", (_, input, expected) => {
    const result = constructOCIDisributionMetadata(input);
    expect(result).toStrictEqual(expected);
  });
});
