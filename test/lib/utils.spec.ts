import { isValidDockerImageReference } from "../../lib/utils";

describe("isValidDockerImageReference", () => {
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
        expect(isValidDockerImageReference(imageName)).toBe(true);
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
        expect(isValidDockerImageReference(imageName)).toBe(false);
      },
    );
  });
});
