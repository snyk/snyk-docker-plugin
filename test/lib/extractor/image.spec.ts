import * as path from "path";
import { extractImageContent } from "../../../lib/extractor";
import { getImageNames, ImageName } from "../../../lib/extractor/image";
import { ExtractAction } from "../../../lib/extractor/types";
import { streamToString } from "../../../lib/stream-utils";
import { ImageType } from "../../../lib/types";

describe("image", () => {
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

    test("ImageName class throws an error when image repository name is more than 255 characters", () => {
      const longImageName = "a".repeat(256);
      expect(() => new ImageName(longImageName)).toThrowError(
        "image repository name is more than 255 characters",
      );
    });

    test("ImageName class defaults tag to 'latest' when no tag or digest is provided", () => {
      const imageName = new ImageName("nginx", {});
      expect(imageName.tag).toEqual("latest");
      expect(imageName.getAllNames()).toEqual(["nginx:latest"]);
    });

    test("ImageName class includes unknown digest in getAllNames()", () => {
      const imageName = new ImageName(
        "nginx:latest@sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        {},
      );
      expect(imageName.digests.unknown).toBeDefined();
      const allNames = imageName.getAllNames();
      expect(allNames).toContain("nginx:latest");
      expect(allNames).toContain(
        "nginx@sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
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

    test.each([
      ["sha256", "no colon"],
      [
        ":abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "colon at start",
      ],
      ["sha256:", "colon at end"],
    ])(
      "ImageDigest class throws error for invalid digest format - %s",
      (digest, _description) => {
        expect(
          () =>
            new ImageName("gcr.io/nginx:1.23.0", {
              manifest: digest,
            }),
        ).toThrowError("invalid digest format");
      },
    );

    test("ImageDigest class throws an error when digest hex length is incorrect", () => {
      expect(
        () =>
          new ImageName("gcr.io/nginx:1.23.0", {
            manifest: "sha256:abcd1234", // Too short for sha256 (should be 64 chars)
          }),
      ).toThrowError(
        "digest algorithm sha256 suggested length 64, but got digest with length 8",
      );
    });

    test.each([
      [
        "GGGG1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "non-hex character G",
      ],
      [
        "ABCD1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "uppercase hex chars",
      ],
    ])(
      "ImageDigest class throws error for invalid hex characters - %s",
      (hexPart, _description) => {
        expect(
          () =>
            new ImageName("gcr.io/nginx:1.23.0", {
              manifest: `sha256:${hexPart}`,
            }),
        ).toThrowError("digest contains invalid characters");
      },
    );
  });

  describe("getImageNames can handle given inputs", () => {
    test("getImageNames return an array with name and tag when only imageNameAndTag option was provided", () => {
      const names = getImageNames(
        { imageNameAndTag: "nginx:latest" },
        undefined,
      );
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

  describe("image extractor", () => {
    const getFixture = (fixturePath) =>
      path.join(__dirname, "../../fixtures", fixturePath);

    test.each([
      ["docker-save", "docker-archives/docker-save/nginx.tar"],
      ["skopeo", "docker-archives/skopeo-copy/nginx.tar"],
    ])(
      "callbacks are issued when files are found (%s archive)",
      async (archiveType, fixturePath) => {
        const extractActions: ExtractAction[] = [
          {
            actionName: "read_as_string",
            filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
            callback: async (stream) => {
              const content = await streamToString(stream);
              expect(content).toEqual("Hello, world!");
              return content;
            },
          },
        ];

        await extractImageContent(
          ImageType.DockerArchive,
          getFixture(fixturePath),
          extractActions,
          {},
        );
      },
    );

    test.each([
      ["docker-save", "docker-archives/docker-save/nginx.tar"],
      ["skopeo", "docker-archives/skopeo-copy/nginx.tar"],
    ])(
      "can read content with multiple callbacks (%s archive)",
      async (archiveType, fixturePath) => {
        const extractActions: ExtractAction[] = [
          {
            actionName: "read_as_string",
            filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
            callback: async (stream) => {
              const content = await streamToString(stream);
              expect(content).toEqual("Hello, world!");
              return content;
            },
          },
          {
            actionName: "read_as_buffer",
            filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
            callback: async (stream) => {
              const content = await streamToString(stream);
              expect(content).toEqual("Hello, world!");
              return `${content} Second callback!`;
            },
          },
        ];

        await extractImageContent(
          ImageType.DockerArchive,
          getFixture(fixturePath),
          extractActions,
          {},
        );
      },
    );

    test("ensure the results are the same for docker and for skopeo docker-archives", async () => {
      const returnedContent = "this is a mock";
      const fileNamePattern = "/snyk/mock.txt";
      const actionName = "find_mock";

      const extractActions: ExtractAction[] = [
        {
          actionName,
          filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
          callback: async () => returnedContent,
        },
      ];

      const dockerResult = await extractImageContent(
        ImageType.DockerArchive,
        getFixture("docker-archives/skopeo-copy/nginx.tar"),
        extractActions,
        {},
      );

      const skopeoResult = await extractImageContent(
        ImageType.DockerArchive,
        getFixture("docker-archives/skopeo-copy/nginx.tar"),
        extractActions,
        {},
      );

      //  Docker and Skopeo docker-archive outputs resolve the same way
      expect(dockerResult).toEqual(skopeoResult);

      const layers = dockerResult.extractedLayers;
      //  ImageId returned as expected
      expect(dockerResult.imageId).toEqual(
        "sha256:ab56bba91343aafcdd94b7a44b42e12f32719b9a2b8579e93017c1280f48e8f3",
      );

      //  The layers returned are as expected
      expect(
        fileNamePattern in layers &&
          actionName in layers[fileNamePattern] &&
          layers[fileNamePattern][actionName] === returnedContent,
      ).toBeTruthy();

      //  Layers match
      expect(dockerResult.manifestLayers).toEqual([
        "ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9.tar",
      ]);

      //  Base image layers match
      expect(dockerResult.rootFsLayers).toEqual([
        "sha256:2db44bce66cde56fca25aeeb7d09dc924b748e3adfe58c9cc3eb2bd2f68a1b68",
        "sha256:16d1b1dd2a23a7a79426299fde8be361194007dfebb3438f96735755283becf8",
        "sha256:ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9",
      ]);

      const foundPackages = Object.keys(
        dockerResult.autoDetectedUserInstructions!.dockerfilePackages,
      ).sort();
      const expectedPackages = [
        "ca-certificates",
        "gettext-base",
        "gnupg1",
        "nginxPackages",
      ].sort();

      expect(foundPackages).toEqual(expectedPackages);
      expect(dockerResult.platform).toEqual(skopeoResult.platform);
    });

    test("extracted oci image content returned as expected", async () => {
      const returnedContent =
        '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:e26d615025f594002683ea9b0104aeb886e0c383fcf96f9e372491beb17678e6","size":971}]}';
      const fileNamePattern = "/snyk/mock.json";
      const actionName = "read_as_string";

      const extractActions: ExtractAction[] = [
        {
          actionName: "read_as_string",
          filePathMatches: (filePath) => filePath === fileNamePattern,
          callback: async (stream) => {
            const content = await streamToString(stream);
            //  Callback is issued when files are found
            expect(content).toEqual(returnedContent);
            return content;
          },
        },
      ];

      const result = await extractImageContent(
        ImageType.OciArchive,
        getFixture("oci-archives/nginx.tar"),
        extractActions,
        {},
      );

      //  ImageId returned as expected
      expect(result.imageId).toEqual(
        "sha256:32cc7aa0cb24d7b4e1907a1a658676aacd676356a6ea818549cdd8a2a38e43b6",
      );
      //  Result has expected structure
      expect(
        "extractedLayers" in result && "manifestLayers" in result,
      ).toBeTruthy();

      const layers = result.extractedLayers;

      //  The layers returned are as expected
      expect(
        fileNamePattern in layers &&
          actionName in layers[fileNamePattern] &&
          layers[fileNamePattern][actionName] === returnedContent,
      ).toBeTruthy();

      //  Manifest returns expected layers content
      expect(result.manifestLayers).toEqual([
        "sha256:dd3ac8106a0bbe43a6e55d2b719fc00a2f8f694e90c7903403e8fdecd2ccc57f",
        "sha256:8de28bdda69b66a8e07b14f03a9762f508bc4caac35cef9543bad53503ce5f53",
        "sha256:a2c431ac2669038db7a758a597c7d1d53cdfb2dd9bf6de2ad3418973569b3fc7",
        "sha256:e070d03fd1b5a05aafc7c16830d80b4ed622d546061fabac8163d3082098a849",
      ]);
    });

    test("correctly handles wrong image type by applying a fallback to the correct one", async () => {
      const extractActions: ExtractAction[] = [
        {
          actionName: "find_mock",
          filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
          callback: async () => "this is a mock",
        },
      ];

      expect(
        async () =>
          await extractImageContent(
            ImageType.OciArchive,
            getFixture("docker-archives/skopeo-copy/nginx.tar"),
            extractActions,
            {},
          ),
      ).not.toThrow(new Error("Invalid OCI archive"));

      expect(
        async () =>
          await extractImageContent(
            ImageType.DockerArchive,
            getFixture("oci-archives/nginx.tar"),
            extractActions,
            {},
          ),
      ).not.toThrow(new Error("Invalid Docker archive"));

      expect(
        async () =>
          await extractImageContent(
            ImageType.DockerArchive,
            getFixture("oci-archives/oci-with-manifest.tar"),
            extractActions,
            {},
          ),
      ).not.toThrow(new Error("Invalid Docker archive"));
    });
  });
});
