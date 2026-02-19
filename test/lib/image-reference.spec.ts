import {
  parseImageReference,
  isValidImageReference,
} from "../../lib/image-reference";

const validSha256 =
  "sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234";

describe("image-reference", () => {
  describe("parseImageReference", () => {
    describe("valid image references", () => {
      it("parses image with tag only", () => {
        expect(parseImageReference("nginx:latest")).toEqual({
          repository: "nginx",
          registry: undefined,
          tag: "latest",
          digest: undefined,
        });
      });

      it("parses image with semantic tag", () => {
        expect(parseImageReference("nginx:1.23.0")).toEqual({
          repository: "nginx",
          registry: undefined,
          tag: "1.23.0",
          digest: undefined,
        });
      });

      it("parses image without tag or digest (repository only)", () => {
        expect(parseImageReference("nginx")).toEqual({
          repository: "nginx",
          registry: undefined,
          tag: undefined,
          digest: undefined,
        });
      });

      it("parses image with digest only", () => {
        expect(parseImageReference(`nginx@${validSha256}`)).toEqual({
          repository: "nginx",
          registry: undefined,
          tag: undefined,
          digest: validSha256,
        });
      });

      it("parses image with tag and digest (name:tag@digest)", () => {
        expect(
          parseImageReference(`nginx:1.23.0@${validSha256}`),
        ).toEqual({
          repository: "nginx",
          registry: undefined,
          tag: "1.23.0",
          digest: validSha256,
        });
      });

      it("parses image with registry (gcr.io)", () => {
        expect(parseImageReference("gcr.io/project/nginx:latest")).toEqual({
          repository: "project/nginx",
          registry: "gcr.io",
          tag: "latest",
          digest: undefined,
        });
      });

      it("parses image with registry and digest", () => {
        expect(
          parseImageReference(`gcr.io/project/nginx:1.23.0@${validSha256}`),
        ).toEqual({
          repository: "project/nginx",
          registry: "gcr.io",
          tag: "1.23.0",
          digest: validSha256,
        });
      });

      it("parses localhost registry with port", () => {
        expect(
          parseImageReference("localhost:5000/foo/bar:tag"),
        ).toEqual({
          repository: "foo/bar",
          registry: "localhost:5000",
          tag: "tag",
          digest: undefined,
        });
      });

      it("parses docker.io style registry", () => {
        expect(
          parseImageReference("docker.io/calico/cni:release-v3.14"),
        ).toEqual({
          repository: "calico/cni",
          registry: "docker.io",
          tag: "release-v3.14",
          digest: undefined,
        });
      });

      it("parses library/ prefix (Docker Hub official images)", () => {
        expect(parseImageReference("library/nginx:latest")).toEqual({
          repository: "library/nginx",
          registry: undefined,
          tag: "latest",
          digest: undefined,
        });
      });

      it("parses docker.io/library/ prefix (Docker Hub official images)", () => {
        expect(parseImageReference("docker.io/library/nginx:latest")).toEqual({
          repository: "library/nginx",
          registry: "docker.io",
          tag: "latest",
          digest: undefined,
        });
      });

      it("parses repository with dots and dashes", () => {
        expect(parseImageReference("my.repo/image-name:tag")).toEqual({
          repository: "image-name",
          registry: "my.repo",
          tag: "tag",
          digest: undefined,
        });
      });

      it("parses IPv6 registry", () => {
        expect(
          parseImageReference("[::1]:5000/foo/bar:latest"),
        ).toEqual({
          repository: "foo/bar",
          registry: "[::1]:5000",
          tag: "latest",
          digest: undefined,
        });
      });

      it("parses tag with dots and dashes", () => {
        expect(parseImageReference("nginx:1.23.0-alpha")).toEqual({
          repository: "nginx",
          registry: undefined,
          tag: "1.23.0-alpha",
          digest: undefined,
        });
      });
    });

    describe("invalid image references", () => {
      it("throws for empty string", () => {
        expect(() => parseImageReference("")).toThrow("image name is empty");
      });

      it("throws for invalid format (no repository)", () => {
        expect(() => parseImageReference(":tag")).toThrow(
          "invalid image reference format",
        );
      });

      it("throws for invalid format (leading slash)", () => {
        expect(() => parseImageReference("/test:unknown")).toThrow(
          "invalid image reference format",
        );
      });

      it("throws for uppercase in repository", () => {
        expect(() => parseImageReference("UPPERCASE")).toThrow(
          "image repository contains uppercase letter",
        );
      });

      it("throws for uppercase in repository path with registry", () => {
        expect(() => parseImageReference("gcr.io/Project/nginx")).toThrow(
          "image repository contains uppercase letter",
        );
      });

      it("throws for invalid digest (too short)", () => {
        expect(() =>
          parseImageReference("nginx@sha256:abc"),
        ).toThrow("invalid image reference format");
      });

      it("throws for malformed reference", () => {
        expect(() => parseImageReference("image:")).toThrow(
          "invalid image reference format",
        );
      });
    });
  });

  describe("isValidImageReference", () => {
    it("returns true for valid references", () => {
      expect(isValidImageReference("nginx:latest")).toBe(true);
      expect(isValidImageReference("nginx")).toBe(true);
      expect(
        isValidImageReference(`nginx:1.23.0@${validSha256}`),
      ).toBe(true);
      expect(isValidImageReference("gcr.io/project/nginx:latest")).toBe(true);
    });

    it("returns false for empty string", () => {
      expect(isValidImageReference("")).toBe(false);
    });

    it("returns false for invalid format", () => {
      expect(isValidImageReference(":tag")).toBe(false);
      expect(isValidImageReference("/invalid")).toBe(false);
    });

    it("returns false for uppercase in repository", () => {
      expect(isValidImageReference("UPPERCASE")).toBe(false);
    });
  });
});

describe("isValidImageReference", () => {
  describe("valid image references", () => {
    const validImages = [
      "nginx",
      "ubuntu",
      "alpine",
      "nginx:latest",
      "ubuntu:20.04",
      "alpine:3.14",
      "library/nginx",
      "library/ubuntu:20.04",
      "docker.io/nginx",
      "docker.io/library/nginx:latest",
      "gcr.io/project-id/image-name",
      "gcr.io/project-id/image-name:tag",
      "registry.hub.docker.com/library/nginx",
      "localhost:5000/myimage",
      "localhost:5000/myimage:latest",
      "registry.example.com/path/to/image",
      "registry.example.com:8080/path/to/image:v1.0",
      "my-registry.com/my-namespace/my-image",
      "my-registry.com/my-namespace/my-image:v2.1.0",
      "nginx@sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
      "ubuntu:20.04@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
      "image_name",
      "image.name",
      "image-name",
      "namespace/image_name.with-dots",
      "registry.com/namespace/image__double_underscore",
      "127.0.0.1:5000/test",
      "[::1]:5000/test",
      "registry.com/a/b/c/d/e/f/image",
      "a.b.c/namespace/image:tag",
    ];

    it.each(validImages)(
      "should return true for valid image reference: %s",
      (imageName) => {
        expect(isValidImageReference(imageName)).toBe(true);
      },
    );
  });

  describe("invalid image references", () => {
    const invalidImages = [
      "/test:unknown",
      "//invalid",
      "invalid//path",
      "UPPERCASE",
      "Invalid:Tag",
      "registry.com/UPPERCASE/image",
      "registry.com/namespace/UPPERCASE",
      "",
      "image:",
      ":tag",
      "image::",
      "registry.com:",
      "registry.com:/image",
      "image@",
      "image@sha256:",
      "image@invalid:digest",
      "registry.com//namespace/image",
      "registry.com/namespace//image",
      ".image",
      "image.",
      "-image",
      "image-",
      "_image",
      "image_",
      "registry-.com/image",
      "registry.com-/image",
      "image:tag@",
      "image:tag@sha256",
      "registry.com:abc/image",
      "registry.com:-1/image",
    ];

    it.each(invalidImages)(
      "should return false for invalid image reference: %s",
      (imageName) => {
        expect(isValidImageReference(imageName)).toBe(false);
      },
    );
  });
});