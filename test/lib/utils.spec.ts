import {
  isValidDockerImageReference,
  RESPONSE_SIZE_LIMITS,
  truncateAdditionalFacts,
} from "../../lib/utils";

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

describe("truncateAdditionalFacts", () => {
  describe("should handle edge cases", () => {
    it("should return empty array for empty input", () => {
      const result = truncateAdditionalFacts([]);
      expect(result).toEqual([]);
    });

    it("should handle facts without data property", () => {
      const facts = [
        { type: "containerConfig" },
        { type: "history", data: null },
        { type: "platform", data: undefined },
      ];
      const result = truncateAdditionalFacts(facts);
      expect(result).toEqual(facts);
    });

    it("should handle unknown fact types", () => {
      const facts = [
        {
          type: "unknownFact",
          data: {
            someField: "some value",
            someArray: Array.from({ length: 2000 }, (_, i) => `item${i}`),
          },
        },
      ];
      const result = truncateAdditionalFacts(facts);
      expect(result).toEqual(facts);
    });
  });

  describe("containerConfig fact", () => {
    it("should pass through containerConfig within limits", () => {
      const facts = [
        {
          type: "containerConfig",
          data: {
            user: "root",
            exposedPorts: ["80/tcp", "443/tcp"],
            env: ["VAR1=value1", "VAR2=value2"],
            entrypoint: ["/bin/sh", "-c"],
            cmd: ["echo", "hello"],
            volumes: ["/data", "/logs"],
            workingDir: "/app",
            stopSignal: "SIGTERM",
          },
        },
      ];
      const result = truncateAdditionalFacts(facts);
      expect(result).toEqual(facts);
    });

    it("should truncate containerConfig arrays when they exceed limits", () => {
      const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;
      const cmdLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.cmd"].limit;
      const entrypointLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.entrypoint"].limit;
      const volumesLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.volumes"].limit;
      const exposedPortsLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.exposedPorts"].limit;

      const largeEnv = Array.from(
        { length: envLimit + 100 },
        (_, i) => `VAR${i}=value${i}`,
      );
      const largeCmd = Array.from(
        { length: cmdLimit + 100 },
        (_, i) => `arg${i}`,
      );
      const largeEntrypoint = Array.from(
        { length: entrypointLimit + 100 },
        (_, i) => `entry${i}`,
      );
      const largeVolumes = Array.from(
        { length: volumesLimit + 100 },
        (_, i) => `/data${i}`,
      );
      const largeExposedPorts = Array.from(
        { length: exposedPortsLimit + 100 },
        (_, i) => `${8000 + i}/tcp`,
      );

      const facts = [
        {
          type: "containerConfig",
          data: {
            env: largeEnv,
            cmd: largeCmd,
            entrypoint: largeEntrypoint,
            volumes: largeVolumes,
            exposedPorts: largeExposedPorts,
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result[0].data.env).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit,
      );
      expect(result[0].data.cmd).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.cmd"].limit,
      );
      expect(result[0].data.entrypoint).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.entrypoint"].limit,
      );
      expect(result[0].data.volumes).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.volumes"].limit,
      );
      expect(result[0].data.exposedPorts).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.exposedPorts"].limit,
      );
      expect(result[0].data.env).toEqual(largeEnv.slice(0, envLimit));
      expect(result[0].data.cmd).toEqual(largeCmd.slice(0, cmdLimit));
    });

    it("should truncate containerConfig string fields when they exceed limits", () => {
      const userLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.user"].limit;
      const workingDirLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.workingDir"].limit;
      const stopSignalLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.stopSignal"].limit;

      const longUser = "a".repeat(userLimit + 976);
      const longWorkingDir = "/very/long/path/".repeat(
        Math.ceil((workingDirLimit + 100) / 16),
      );
      const longStopSignal = "SIGNAL".repeat(
        Math.ceil((stopSignalLimit + 50) / 6),
      );

      const facts = [
        {
          type: "containerConfig",
          data: {
            user: longUser,
            workingDir: longWorkingDir,
            stopSignal: longStopSignal,
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result[0].data.user).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.user"].limit,
      );
      expect(result[0].data.workingDir).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.workingDir"].limit,
      );
      expect(result[0].data.stopSignal).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.stopSignal"].limit,
      );
      expect(result[0].data.user).toBe(longUser.substring(0, userLimit));
      expect(result[0].data.workingDir).toBe(
        longWorkingDir.substring(0, workingDirLimit),
      );
      expect(result[0].data.stopSignal).toBe(
        longStopSignal.substring(0, stopSignalLimit),
      );
    });

    it("should truncate individual array elements when they exceed string limits", () => {
      const longEnvVars = [
        "SHORT_VAR=value",
        "LONG_VAR=" +
          "x".repeat(
            RESPONSE_SIZE_LIMITS["containerConfig.data.env[*]"].limit + 976,
          ),
        "ANOTHER_LONG=" +
          "y".repeat(
            RESPONSE_SIZE_LIMITS["containerConfig.data.env[*]"].limit + 1976,
          ),
      ];
      const facts = [
        {
          type: "containerConfig",
          data: {
            env: longEnvVars,
          },
        },
      ];
      const result = truncateAdditionalFacts(facts);
      expect(result[0].data.env[0]).toBe("SHORT_VAR=value");
      expect(result[0].data.env[1]).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.env[*]"].limit,
      );
      expect(result[0].data.env[2]).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.env[*]"].limit,
      );
      const envElementLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.env[*]"].limit;
      expect(result[0].data.env[1]).toBe(
        longEnvVars[1].substring(0, envElementLimit),
      );
      expect(result[0].data.env[2]).toBe(
        longEnvVars[2].substring(0, envElementLimit),
      );
    });

    it("should truncate all containerConfig array elements when they exceed string limits", () => {
      const exposedPortsElementLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.exposedPorts[*]"].limit;
      const entrypointElementLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.entrypoint[*]"].limit;
      const cmdElementLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.cmd[*]"].limit;
      const volumesElementLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.volumes[*]"].limit;
      const longPort = "x".repeat(exposedPortsElementLimit + 36);
      const longEntrypoint = "y".repeat(entrypointElementLimit + 976);
      const longCmd = "z".repeat(cmdElementLimit + 476);
      const longVolume = "w".repeat(volumesElementLimit + 1976);

      const facts = [
        {
          type: "containerConfig",
          data: {
            exposedPorts: ["80/tcp", longPort + "/tcp", "443/tcp"],
            entrypoint: ["/bin/sh", longEntrypoint, "-c"],
            cmd: ["echo", longCmd, "world"],
            volumes: ["/data", longVolume, "/logs"],
          },
        },
      ];
      const result = truncateAdditionalFacts(facts);
      expect(result[0].data.exposedPorts[0]).toBe("80/tcp");
      expect(result[0].data.exposedPorts[1]).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.exposedPorts[*]"].limit,
      );
      expect(result[0].data.exposedPorts[1]).toBe(
        (longPort + "/tcp").substring(
          0,
          RESPONSE_SIZE_LIMITS["containerConfig.data.exposedPorts[*]"].limit,
        ),
      );
      expect(result[0].data.exposedPorts[2]).toBe("443/tcp");
      expect(result[0].data.entrypoint[0]).toBe("/bin/sh");
      expect(result[0].data.entrypoint[1]).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.entrypoint[*]"].limit,
      );
      expect(result[0].data.entrypoint[1]).toBe(
        longEntrypoint.substring(
          0,
          RESPONSE_SIZE_LIMITS["containerConfig.data.entrypoint[*]"].limit,
        ),
      );
      expect(result[0].data.entrypoint[2]).toBe("-c");
      expect(result[0].data.cmd[0]).toBe("echo");
      expect(result[0].data.cmd[1]).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.cmd[*]"].limit,
      );
      expect(result[0].data.cmd[1]).toBe(
        longCmd.substring(
          0,
          RESPONSE_SIZE_LIMITS["containerConfig.data.cmd[*]"].limit,
        ),
      );
      expect(result[0].data.cmd[2]).toBe("world");
      expect(result[0].data.volumes[0]).toBe("/data");
      expect(result[0].data.volumes[1]).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.volumes[*]"].limit,
      );
      expect(result[0].data.volumes[1]).toBe(
        longVolume.substring(
          0,
          RESPONSE_SIZE_LIMITS["containerConfig.data.volumes[*]"].limit,
        ),
      );
      expect(result[0].data.volumes[2]).toBe("/logs");
    });
  });

  describe("history fact", () => {
    it("should pass through history within limits", () => {
      const facts = [
        {
          type: "history",
          data: [
            {
              created: "2023-01-01T00:00:00Z",
              author: "test author",
              createdBy: "RUN echo test",
              comment: "Test comment",
              emptyLayer: false,
            },
            {
              created: "2023-01-02T00:00:00Z",
              author: "another author",
              createdBy: "COPY . /app",
              comment: "Copy files",
              emptyLayer: true,
            },
          ],
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toEqual(facts);
    });

    it("should truncate history array when it exceeds limit", () => {
      const historyLimit = RESPONSE_SIZE_LIMITS["history.data"].limit;
      const largeHistory = Array.from(
        { length: historyLimit + 200 },
        (_, i) => ({
          created: `2023-01-01T00:00:${i.toString().padStart(2, "0")}Z`,
          author: `author${i}`,
          createdBy: `RUN echo step${i}`,
          comment: `Step ${i}`,
          emptyLayer: false,
        }),
      );

      const facts = [
        {
          type: "history",
          data: largeHistory,
        },
      ];
      const result = truncateAdditionalFacts(facts);
      expect(result[0].data).toHaveLength(
        RESPONSE_SIZE_LIMITS["history.data"].limit,
      );
      expect(result[0].data).toEqual(largeHistory.slice(0, historyLimit));
    });

    it("should truncate history item string fields when they exceed limits", () => {
      const facts = [
        {
          type: "history",
          data: [
            {
              author: "a".repeat(
                RESPONSE_SIZE_LIMITS["history.data[*].author"].limit + 72,
              ),
              createdBy: "b".repeat(
                RESPONSE_SIZE_LIMITS["history.data[*].createdBy"].limit + 72,
              ),
              comment: "c".repeat(
                RESPONSE_SIZE_LIMITS["history.data[*].comment"].limit + 904,
              ),
            },
            {
              author: "short",
              createdBy: "also short",
              comment: "normal comment",
            },
          ],
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result[0].data[0].author).toHaveLength(
        RESPONSE_SIZE_LIMITS["history.data[*].author"].limit,
      );
      expect(result[0].data[0].createdBy).toHaveLength(
        RESPONSE_SIZE_LIMITS["history.data[*].createdBy"].limit,
      );
      expect(result[0].data[0].comment).toHaveLength(
        RESPONSE_SIZE_LIMITS["history.data[*].comment"].limit,
      );
      expect(result[0].data[1].author).toBe("short");
      expect(result[0].data[1].createdBy).toBe("also short");
      expect(result[0].data[1].comment).toBe("normal comment");
      expect(result[0].data[0].author).toBe(
        "a".repeat(RESPONSE_SIZE_LIMITS["history.data[*].author"].limit),
      );
      expect(result[0].data[0].createdBy).toBe(
        "b".repeat(RESPONSE_SIZE_LIMITS["history.data[*].createdBy"].limit),
      );
      expect(result[0].data[0].comment).toBe(
        "c".repeat(RESPONSE_SIZE_LIMITS["history.data[*].comment"].limit),
      );
    });
  });

  describe("multiple facts", () => {
    it("should handle multiple fact types correctly", () => {
      const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;
      const historyLimit = RESPONSE_SIZE_LIMITS["history.data"].limit;

      const largeEnv = Array.from(
        { length: envLimit + 100 },
        (_, i) => `VAR${i}=value${i}`,
      );
      const largeHistory = Array.from(
        { length: historyLimit + 200 },
        (_, i) => ({
          author: `author${i}`,
          createdBy: `RUN step${i}`,
        }),
      );

      const facts = [
        {
          type: "containerConfig",
          data: {
            env: largeEnv,
            user: "root",
          },
        },
        {
          type: "history",
          data: largeHistory,
        },
        {
          type: "platform",
          data: {
            os: "linux",
            architecture: "amd64",
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result[0].data.env).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit,
      );
      expect(result[0].data.user).toBe("root");
      expect(result[1].data).toHaveLength(
        RESPONSE_SIZE_LIMITS["history.data"].limit,
      );
      expect(result[2]).toEqual(facts[2]);
    });

    it("should preserve fact structure and other properties", () => {
      const facts = [
        {
          type: "containerConfig",
          data: {
            env: Array.from(
              {
                length:
                  RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit + 100,
              },
              (_, i) => `VAR${i}=value${i}`,
            ),
          },
          metadata: { source: "dockerfile" },
          version: "1.0",
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result[0].type).toBe("containerConfig");
      expect(result[0].metadata).toEqual({ source: "dockerfile" });
      expect(result[0].version).toBe("1.0");
      expect(result[0].data.env).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit,
      );
    });

    it("should selectively truncate only fields that exceed limits (mix and match)", () => {
      const longComment = "x".repeat(
        RESPONSE_SIZE_LIMITS["history.data[*].comment"].limit + 904,
      );
      const longUser = "y".repeat(
        RESPONSE_SIZE_LIMITS["containerConfig.data.user"].limit + 976,
      );
      const normalEnv = ["VAR1=value1", "VAR2=value2"];
      const normalAuthor = "normal author";

      const facts = [
        {
          type: "containerConfig",
          data: {
            user: longUser,
            env: normalEnv,
            cmd: ["echo", "hello"],
            workingDir: "/app",
            stopSignal: "SIGTERM",
          },
        },
        {
          type: "history",
          data: [
            {
              author: normalAuthor,
              createdBy: "RUN apt-get update",
              comment: longComment,
              created: "2023-01-01T00:00:00Z",
              emptyLayer: false,
            },
            {
              author: "another author",
              createdBy: "COPY . /app",
              comment: "short comment",
            },
          ],
        },
        {
          type: "platform",
          data: {
            os: "linux",
            architecture: "amd64",
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);

      expect(result[0].data.user).toHaveLength(
        RESPONSE_SIZE_LIMITS["containerConfig.data.user"].limit,
      );
      expect(result[0].data.user).toBe(
        longUser.substring(
          0,
          RESPONSE_SIZE_LIMITS["containerConfig.data.user"].limit,
        ),
      );
      expect(result[0].data.env).toEqual(normalEnv);
      expect(result[0].data.cmd).toEqual(["echo", "hello"]);
      expect(result[0].data.workingDir).toBe("/app");
      expect(result[0].data.stopSignal).toBe("SIGTERM");
      expect(result[1].data).toHaveLength(2);
      expect(result[1].data[0].author).toBe(normalAuthor);
      expect(result[1].data[0].createdBy).toBe("RUN apt-get update");
      expect(result[1].data[0].comment).toHaveLength(
        RESPONSE_SIZE_LIMITS["history.data[*].comment"].limit,
      );
      expect(result[1].data[0].comment).toBe(
        longComment.substring(
          0,
          RESPONSE_SIZE_LIMITS["history.data[*].comment"].limit,
        ),
      );
      expect(result[1].data[0].created).toBe("2023-01-01T00:00:00Z");
      expect(result[1].data[0].emptyLayer).toBe(false);
      expect(result[1].data[1].author).toBe("another author");
      expect(result[1].data[1].createdBy).toBe("COPY . /app");
      expect(result[1].data[1].comment).toBe("short comment");
      expect(result[2]).toEqual(facts[2]);
    });
  });

  describe("pluginWarnings fact", () => {
    it("should not add pluginWarnings fact when no truncation occurs", () => {
      const facts = [
        {
          type: "containerConfig",
          data: {
            user: "root",
            env: ["VAR1=value1", "VAR2=value2"],
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(1);
      expect(result.find((f) => f.type === "pluginWarnings")).toBeUndefined();
    });

    it("should add pluginWarnings fact when array truncation occurs", () => {
      const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;
      const largeEnv = Array.from(
        { length: envLimit + 100 },
        (_, i) => `VAR${i}=value${i}`,
      );
      const facts = [
        {
          type: "containerConfig",
          data: {
            env: largeEnv,
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(2);
      const warningsFact = result.find((f) => f.type === "pluginWarnings");
      expect(warningsFact).toBeDefined();
      expect(warningsFact.data.truncatedFacts).toEqual({
        "containerConfig.data.env": { type: "array", countAboveLimit: 100 },
      });
    });

    it("should add pluginWarnings fact when string truncation occurs", () => {
      const longUser = "a".repeat(
        RESPONSE_SIZE_LIMITS["containerConfig.data.user"].limit + 976,
      );

      const facts = [
        {
          type: "containerConfig",
          data: {
            user: longUser,
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(2);
      const warningsFact = result.find((f) => f.type === "pluginWarnings");
      expect(warningsFact).toBeDefined();
      expect(warningsFact.data.truncatedFacts).toEqual({
        "containerConfig.data.user": { type: "string", countAboveLimit: 976 },
      });
    });

    it("should track maximum string truncation for array elements", () => {
      const shortEnv = "SHORT=value";
      const envElementLimit =
        RESPONSE_SIZE_LIMITS["containerConfig.data.env[*]"].limit;
      const mediumEnv = "MEDIUM=" + "x".repeat(envElementLimit + 483);
      const longEnv = "LONG=" + "x".repeat(envElementLimit + 981);
      const facts = [
        {
          type: "containerConfig",
          data: {
            env: [shortEnv, mediumEnv, longEnv],
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(2);
      const warningsFact = result.find((f) => f.type === "pluginWarnings");
      expect(warningsFact).toBeDefined();
      const expectedCountAboveLimit = longEnv.length - envElementLimit;
      expect(warningsFact.data.truncatedFacts).toEqual({
        "containerConfig.data.env[*]": {
          type: "string",
          countAboveLimit: expectedCountAboveLimit,
        },
      });
    });

    it("should track multiple truncation types", () => {
      const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;
      const largeEnv = Array.from(
        { length: envLimit + 100 },
        (_, i) => `VAR${i}=value${i}`,
      );
      const longUser = "a".repeat(
        RESPONSE_SIZE_LIMITS["containerConfig.data.user"].limit + 976,
      );
      const historyLimit = RESPONSE_SIZE_LIMITS["history.data"].limit;
      const largeHistory = Array.from(
        { length: historyLimit + 200 },
        (_, i) => ({
          created: `2023-01-01T00:00:${i.toString().padStart(2, "0")}Z`,
          author: `author${i}`,
          createdBy: `RUN echo step${i}`,
          comment: `Step ${i}`,
          emptyLayer: false,
        }),
      );

      const facts = [
        {
          type: "containerConfig",
          data: {
            user: longUser,
            env: largeEnv,
          },
        },
        {
          type: "history",
          data: largeHistory,
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(3);
      const warningsFact = result.find((f) => f.type === "pluginWarnings");
      expect(warningsFact).toBeDefined();
      expect(warningsFact.data.truncatedFacts).toEqual({
        "containerConfig.data.user": { type: "string", countAboveLimit: 976 },
        "containerConfig.data.env": { type: "array", countAboveLimit: 100 },
        "history.data": { type: "array", countAboveLimit: 200 },
      });
    });

    it("should track nested string truncation in history objects", () => {
      const authorLimit = RESPONSE_SIZE_LIMITS["history.data[*].author"].limit;
      const createdByLimit =
        RESPONSE_SIZE_LIMITS["history.data[*].createdBy"].limit;
      const commentLimit =
        RESPONSE_SIZE_LIMITS["history.data[*].comment"].limit;
      const longAuthor = "a".repeat(authorLimit + 72);
      const veryLongCreatedBy = "RUN " + "x".repeat(createdByLimit + 176 - 4);
      const longComment = "x".repeat(commentLimit + 904);
      const facts = [
        {
          type: "history",
          data: [
            {
              created: "2023-01-01T00:00:00Z",
              author: "short author",
              createdBy: "RUN echo test",
              comment: "short comment",
              emptyLayer: false,
            },
            {
              created: "2023-01-02T00:00:00Z",
              author: longAuthor,
              createdBy: veryLongCreatedBy,
              comment: longComment,
              emptyLayer: true,
            },
          ],
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(2);
      const warningsFact = result.find((f) => f.type === "pluginWarnings");
      expect(warningsFact).toBeDefined();
      expect(warningsFact.data.truncatedFacts).toEqual({
        "history.data[*].author": { type: "string", countAboveLimit: 72 },
        "history.data[*].createdBy": { type: "string", countAboveLimit: 176 },
        "history.data[*].comment": { type: "string", countAboveLimit: 904 },
      });
    });

    it("should track maximum truncation across multiple history objects", () => {
      const authorLimit = RESPONSE_SIZE_LIMITS["history.data[*].author"].limit;
      const mediumAuthor = "a".repeat(authorLimit + 22);
      const longAuthor = "b".repeat(authorLimit + 72);
      const facts = [
        {
          type: "history",
          data: [
            {
              created: "2023-01-01T00:00:00Z",
              author: mediumAuthor,
              createdBy: "RUN echo test1",
              comment: "comment1",
              emptyLayer: false,
            },
            {
              created: "2023-01-02T00:00:00Z",
              author: longAuthor,
              createdBy: "RUN echo test2",
              comment: "comment2",
              emptyLayer: true,
            },
          ],
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(2);
      const warningsFact = result.find((f) => f.type === "pluginWarnings");
      expect(warningsFact).toBeDefined();
      expect(warningsFact.data.truncatedFacts).toEqual({
        "history.data[*].author": { type: "string", countAboveLimit: 72 },
      });
    });

    it("should merge truncatedFacts into an existing pluginWarnings fact", () => {
      const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;
      const largeEnv = Array.from(
        { length: envLimit + 100 },
        (_, i) => `VAR${i}=value${i}`,
      );

      const facts = [
        {
          type: "containerConfig",
          data: {
            env: largeEnv,
          },
        },
        {
          type: "pluginWarnings",
          data: {
            parameterChecks: ["some warning about a parameter"],
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);

      const warningsFacts = result.filter((f) => f.type === "pluginWarnings");
      expect(warningsFacts).toHaveLength(1);

      const warningsFact = warningsFacts[0];
      expect(warningsFact.data.parameterChecks).toEqual([
        "some warning about a parameter",
      ]);
      expect(warningsFact.data.truncatedFacts).toEqual({
        "containerConfig.data.env": { type: "array", countAboveLimit: 100 },
      });
    });

    it("should pass through objects without matching limits unchanged", () => {
      const complexObject = {
        _internal: new Map([["key", "value"]]),
        _graph: { nodes: [], edges: [] },
        publicAPI: "should remain",
      };
      const facts = [
        {
          type: "depGraph",
          data: complexObject,
        },
      ];
      const result = truncateAdditionalFacts(facts);
      expect(result).toHaveLength(1);
      expect(result[0].data).toBe(complexObject);
      expect(result.find((f) => f.type === "pluginWarnings")).toBeUndefined();
    });
  });
});
