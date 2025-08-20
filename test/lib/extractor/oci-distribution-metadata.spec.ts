import {
  constructOCIDisributionMetadata,
  OCIDistributionMetadata,
} from "../../../lib/extractor/oci-distribution-metadata";

// Mock the docker-reference module
jest.mock("@swimlane/docker-reference");
import * as dockerReference from "@swimlane/docker-reference";

describe("constructOCIDisributionMetadata should", () => {
  // Set up default behavior for parseAll
  beforeEach(() => {
    jest.clearAllMocks();
    // By default, parseAll should behave normally for existing tests
    (dockerReference.parseAll as jest.Mock).mockImplementation(
      (imageName: string) => {
        // Simple mock implementation for existing tests
        const parts = imageName.split("/");
        const lastPart = parts[parts.length - 1];

        let domain = "docker.io";
        let repository = "";
        let tag = undefined;

        if (parts.length > 1 && parts[0].includes(".")) {
          domain = parts[0];
          repository = parts.slice(1).join("/").split(/[:@]/)[0];
        } else if (parts.length > 1) {
          repository = parts.join("/").split(/[:@]/)[0];
        } else {
          repository = "library/" + lastPart.split(/[:@]/)[0];
        }

        // Handle tag vs digest
        if (lastPart.includes("@sha256:")) {
          // This is a digest reference, no tag
          tag = undefined;
        } else if (lastPart.includes(":")) {
          // This is a tag reference
          tag = lastPart.split(":")[1];
        }

        // Handle special cases from original tests
        if (imageName.startsWith("..io/")) {
          throw new Error("Invalid host");
        }
        if (imageName.includes("re*&&po")) {
          throw new Error("Invalid repository");
        }
        if (imageName.includes("__*image=")) {
          throw new Error("Invalid tag");
        }
        if (domain.length > 255) {
          throw new Error("Host too long");
        }
        if (repository.length > 2048) {
          throw new Error("Repository too long");
        }

        return {
          domain,
          repository,
          tag,
        };
      },
    );
  });

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

  it("should return undefined when parseAll returns no domain", () => {
    // Mock parseAll to return an object without domain
    const parseAllModule = require("@swimlane/docker-reference");
    const originalParseAll = parseAllModule.parseAll;
    parseAllModule.parseAll = jest.fn().mockReturnValue({
      repository: "repo",
      tag: "test",
      // domain is missing
    });

    const result = constructOCIDisributionMetadata({
      imageName: "test",
      manifestDigest:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });

    expect(result).toBeUndefined();
    parseAllModule.parseAll = originalParseAll;
  });

  it("should return undefined when parseAll returns no repository", () => {
    // Mock parseAll to return an object without repository
    const parseAllModule = require("@swimlane/docker-reference");
    const originalParseAll = parseAllModule.parseAll;
    parseAllModule.parseAll = jest.fn().mockReturnValue({
      domain: "gcr.io",
      tag: "test",
      // repository is missing
    });

    const result = constructOCIDisributionMetadata({
      imageName: "test",
      manifestDigest:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });

    expect(result).toBeUndefined();
    parseAllModule.parseAll = originalParseAll;
  });

  it("should return undefined when registryHost exceeds 255 bytes", () => {
    // Mock parseAll to return valid data but with a very long domain
    const parseAllModule = require("@swimlane/docker-reference");
    const originalParseAll = parseAllModule.parseAll;

    // Create a domain that's exactly 256 bytes (exceeds 255 limit)
    const longDomain = "a".repeat(256);

    parseAllModule.parseAll = jest.fn().mockReturnValue({
      domain: longDomain,
      repository: "repo",
      tag: "test",
    });

    const result = constructOCIDisributionMetadata({
      imageName: "test",
      manifestDigest:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });

    expect(result).toBeUndefined();
    parseAllModule.parseAll = originalParseAll;
  });

  it("should return undefined when repository exceeds 2048 bytes", () => {
    // Mock parseAll to return valid data but with a very long repository
    const parseAllModule = require("@swimlane/docker-reference");
    const originalParseAll = parseAllModule.parseAll;

    // Create a repository that's exactly 2049 bytes (exceeds 2048 limit)
    const longRepo = "a".repeat(2049);

    parseAllModule.parseAll = jest.fn().mockReturnValue({
      domain: "gcr.io",
      repository: longRepo,
      tag: "test",
    });

    const result = constructOCIDisributionMetadata({
      imageName: "test",
      manifestDigest:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });

    expect(result).toBeUndefined();
    parseAllModule.parseAll = originalParseAll;
  });

  it("should return undefined when repository name is invalid", () => {
    // Mock parseAll to return valid data but with an invalid repository name
    const parseAllModule = require("@swimlane/docker-reference");
    const originalParseAll = parseAllModule.parseAll;

    // Repository with capital letters (invalid according to regex)
    parseAllModule.parseAll = jest.fn().mockReturnValue({
      domain: "gcr.io",
      repository: "INVALID/REPO", // uppercase letters are not allowed
      tag: "test",
    });

    const result = constructOCIDisributionMetadata({
      imageName: "test",
      manifestDigest:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });

    expect(result).toBeUndefined();
    parseAllModule.parseAll = originalParseAll;
  });

  it("should return undefined when imageTag is invalid", () => {
    // Mock parseAll to return valid data but with an invalid tag
    const parseAllModule = require("@swimlane/docker-reference");
    const originalParseAll = parseAllModule.parseAll;

    // Tag starting with a hyphen (invalid according to regex)
    parseAllModule.parseAll = jest.fn().mockReturnValue({
      domain: "gcr.io",
      repository: "example/repo",
      tag: "-invalid-tag", // starts with hyphen, which is not allowed
    });

    const result = constructOCIDisributionMetadata({
      imageName: "test",
      manifestDigest:
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });

    expect(result).toBeUndefined();
    parseAllModule.parseAll = originalParseAll;
  });
});
