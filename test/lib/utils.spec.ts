import {
  isValidDockerImageReference,
  validateSizeConstraintsContainerConfig,
  validateSizeConstraintsHistory,
} from "../../lib/utils";
import { ContainerConfig, HistoryEntry } from "../../lib/extractor/types";

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

describe("validateSizeConstraintsContainerConfig", () => {
  it("should return undefined for undefined input", () => {
    const result = validateSizeConstraintsContainerConfig(undefined);
    expect(result).toBeUndefined();
  });

  it("should pass through config within limits", () => {
    const config: ContainerConfig = {
      Env: ["VAR1=value1", "VAR2=value2"],
      Cmd: ["echo", "hello"],
      Entrypoint: ["/bin/sh"],
      ExposedPorts: { "80/tcp": {}, "443/tcp": {} },
      Volumes: { "/data": {}, "/logs": {} },
    };

    const result = validateSizeConstraintsContainerConfig(config);
    expect(result).toEqual(config);
  });

  it("should truncate env array when it exceeds limit", () => {
    const largeEnvArray = Array.from(
      { length: 600 },
      (_, i) => `VAR${i}=value${i}`,
    );
    const config: ContainerConfig = {
      Env: largeEnvArray,
    };

    const consoleSpy = jest.spyOn(console, "warn").mockImplementation();
    const result = validateSizeConstraintsContainerConfig(config);

    expect(result?.Env!.length).toBeLessThan(600);
    expect(result?.Env).toEqual(largeEnvArray.slice(0, result?.Env!.length));
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("Container config env truncated from 600 to"),
    );

    consoleSpy.mockRestore();
  });

  it("should truncate exposed ports when they exceed limit", () => {
    const largeExposedPorts: { [port: string]: object } = {};
    for (let i = 0; i < 600; i++) {
      largeExposedPorts[`${8000 + i}/tcp`] = {};
    }
    const config: ContainerConfig = {
      ExposedPorts: largeExposedPorts,
    };

    const consoleSpy = jest.spyOn(console, "warn").mockImplementation();
    const result = validateSizeConstraintsContainerConfig(config);

    expect(Object.keys(result?.ExposedPorts || {}).length).toBeLessThan(600);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "Container config exposedPorts truncated from 600 to",
      ),
    );

    consoleSpy.mockRestore();
  });

  it("should truncate cmd array when it exceeds limit", () => {
    const largeCmdArray = Array.from({ length: 600 }, (_, i) => `arg${i}`);
    const config: ContainerConfig = {
      Cmd: largeCmdArray,
    };

    const consoleSpy = jest.spyOn(console, "warn").mockImplementation();
    const result = validateSizeConstraintsContainerConfig(config);

    expect(result?.Cmd!.length).toBeLessThan(600);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("Container config cmd truncated from 600 to"),
    );

    consoleSpy.mockRestore();
  });

  it("should truncate entrypoint array when it exceeds limit", () => {
    const largeEntrypointArray = Array.from(
      { length: 600 },
      (_, i) => `entry${i}`,
    );
    const config: ContainerConfig = {
      Entrypoint: largeEntrypointArray,
    };

    const consoleSpy = jest.spyOn(console, "warn").mockImplementation();
    const result = validateSizeConstraintsContainerConfig(config);

    expect(result?.Entrypoint!.length).toBeLessThan(600);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "Container config entrypoint truncated from 600 to",
      ),
    );

    consoleSpy.mockRestore();
  });

  it("should truncate volumes when they exceed limit", () => {
    const largeVolumes: { [path: string]: object } = {};
    for (let i = 0; i < 600; i++) {
      largeVolumes[`/data${i}`] = {};
    }
    const config: ContainerConfig = {
      Volumes: largeVolumes,
    };

    const consoleSpy = jest.spyOn(console, "warn").mockImplementation();
    const result = validateSizeConstraintsContainerConfig(config);

    expect(Object.keys(result?.Volumes || {}).length).toBeLessThan(600);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("Container config volumes truncated from 600 to"),
    );

    consoleSpy.mockRestore();
  });
});

describe("validateSizeConstraintsHistory", () => {
  it("should return undefined for undefined input", () => {
    const result = validateSizeConstraintsHistory(undefined);
    expect(result).toBeUndefined();
  });

  it("should pass through history within limits", () => {
    const history: HistoryEntry[] = [
      {
        created: "2023-01-01T00:00:00Z",
        author: "test",
        created_by: "RUN echo test",
      },
      {
        created: "2023-01-02T00:00:00Z",
        author: "test2",
        created_by: "RUN echo test2",
      },
    ];

    const result = validateSizeConstraintsHistory(history);
    expect(result).toEqual(history);
  });

  it("should truncate history array when it exceeds limit", () => {
    const largeHistoryArray: HistoryEntry[] = Array.from(
      { length: 1200 },
      (_, i) => ({
        created: `2023-01-01T00:00:${i.toString().padStart(2, "0")}Z`,
        author: `author${i}`,
        created_by: `RUN echo step${i}`,
        comment: `Step ${i}`,
        empty_layer: false,
      }),
    );

    const consoleSpy = jest.spyOn(console, "warn").mockImplementation();
    const result = validateSizeConstraintsHistory(largeHistoryArray);

    expect(result!.length).toBeLessThan(1200);
    expect(result).toEqual(largeHistoryArray.slice(0, result!.length));
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("History array truncated from 1200 to"),
    );

    consoleSpy.mockRestore();
  });
});
