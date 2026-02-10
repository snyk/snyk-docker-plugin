import {
  isValidDockerImageReference,
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
      expect(result).toEqual(facts); // Should pass through unchanged
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
      const largeEnv = Array.from({ length: 600 }, (_, i) => `VAR${i}=value${i}`);
      const largeCmd = Array.from({ length: 600 }, (_, i) => `arg${i}`);
      const largeEntrypoint = Array.from({ length: 600 }, (_, i) => `entry${i}`);
      const largeVolumes = Array.from({ length: 600 }, (_, i) => `/data${i}`);
      const largeExposedPorts = Array.from({ length: 600 }, (_, i) => `${8000 + i}/tcp`);

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
      
      expect(result[0].data.env).toHaveLength(500);
      expect(result[0].data.cmd).toHaveLength(500);
      expect(result[0].data.entrypoint).toHaveLength(500);
      expect(result[0].data.volumes).toHaveLength(500);
      expect(result[0].data.exposedPorts).toHaveLength(500);
      
      // Verify truncated arrays contain the first N elements
      expect(result[0].data.env).toEqual(largeEnv.slice(0, 500));
      expect(result[0].data.cmd).toEqual(largeCmd.slice(0, 500));
    });

    it("should truncate containerConfig string fields when they exceed limits", () => {
      const longUser = "a".repeat(2000);
      const longWorkingDir = "/very/long/path/".repeat(100);
      const longStopSignal = "VERY_LONG_SIGNAL_NAME".repeat(10);

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
      
      expect(result[0].data.user).toHaveLength(1024);
      expect(result[0].data.workingDir).toHaveLength(1024);
      expect(result[0].data.stopSignal).toHaveLength(128);
      
      // Verify truncated strings contain the first N characters
      expect(result[0].data.user).toBe(longUser.substring(0, 1024));
      expect(result[0].data.workingDir).toBe(longWorkingDir.substring(0, 1024));
      expect(result[0].data.stopSignal).toBe(longStopSignal.substring(0, 128));
    });

    it("should truncate individual array elements when they exceed string limits", () => {
      const longEnvVars = [
        "SHORT_VAR=value",
        "LONG_VAR=" + "x".repeat(2000),
        "ANOTHER_LONG=" + "y".repeat(3000),
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
      
      expect(result[0].data.env[0]).toBe("SHORT_VAR=value"); // Unchanged
      expect(result[0].data.env[1]).toHaveLength(1024); // Truncated
      expect(result[0].data.env[2]).toHaveLength(1024); // Truncated
      
      // Verify truncated elements contain the first N characters
      expect(result[0].data.env[1]).toBe(longEnvVars[1].substring(0, 1024));
      expect(result[0].data.env[2]).toBe(longEnvVars[2].substring(0, 1024));
    });

    it("should truncate all containerConfig array elements when they exceed string limits", () => {
      const longPort = "x".repeat(100); // Exceeds 64 limit for exposedPorts
      const longEntrypoint = "y".repeat(2000); // Exceeds 1024 limit for entrypoint
      const longCmd = "z".repeat(1500); // Exceeds 1024 limit for cmd
      const longVolume = "w".repeat(3000); // Exceeds 1024 limit for volumes

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
      
      // Verify exposedPorts array elements (64 char limit)
      expect(result[0].data.exposedPorts[0]).toBe("80/tcp"); // Unchanged
      expect(result[0].data.exposedPorts[1]).toHaveLength(64); // Truncated
      expect(result[0].data.exposedPorts[1]).toBe((longPort + "/tcp").substring(0, 64));
      expect(result[0].data.exposedPorts[2]).toBe("443/tcp"); // Unchanged
      
      // Verify entrypoint array elements (1024 char limit)
      expect(result[0].data.entrypoint[0]).toBe("/bin/sh"); // Unchanged
      expect(result[0].data.entrypoint[1]).toHaveLength(1024); // Truncated
      expect(result[0].data.entrypoint[1]).toBe(longEntrypoint.substring(0, 1024));
      expect(result[0].data.entrypoint[2]).toBe("-c"); // Unchanged
      
      // Verify cmd array elements (1024 char limit)
      expect(result[0].data.cmd[0]).toBe("echo"); // Unchanged
      expect(result[0].data.cmd[1]).toHaveLength(1024); // Truncated
      expect(result[0].data.cmd[1]).toBe(longCmd.substring(0, 1024));
      expect(result[0].data.cmd[2]).toBe("world"); // Unchanged
      
      // Verify volumes array elements (1024 char limit)
      expect(result[0].data.volumes[0]).toBe("/data"); // Unchanged
      expect(result[0].data.volumes[1]).toHaveLength(1024); // Truncated
      expect(result[0].data.volumes[1]).toBe(longVolume.substring(0, 1024));
      expect(result[0].data.volumes[2]).toBe("/logs"); // Unchanged
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
      const largeHistory = Array.from({ length: 1200 }, (_, i) => ({
        created: `2023-01-01T00:00:${i.toString().padStart(2, "0")}Z`,
        author: `author${i}`,
        createdBy: `RUN echo step${i}`,
        comment: `Step ${i}`,
        emptyLayer: false,
      }));

      const facts = [
        {
          type: "history",
          data: largeHistory,
        },
      ];

      const result = truncateAdditionalFacts(facts);
      
      expect(result[0].data).toHaveLength(1000);
      // Verify truncated array contains the first 1000 elements
      expect(result[0].data).toEqual(largeHistory.slice(0, 1000));
    });

    it("should truncate history item string fields when they exceed limits", () => {
      const facts = [
        {
          type: "history",
          data: [
            {
              author: "a".repeat(200), // Exceeds 128 limit
              createdBy: "b".repeat(200), // Exceeds 128 limit  
              comment: "c".repeat(5000), // Exceeds 4096 limit
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
      
      expect(result[0].data[0].author).toHaveLength(128);
      expect(result[0].data[0].createdBy).toHaveLength(128);
      expect(result[0].data[0].comment).toHaveLength(4096);
      
      // Second item should be unchanged
      expect(result[0].data[1].author).toBe("short");
      expect(result[0].data[1].createdBy).toBe("also short");
      expect(result[0].data[1].comment).toBe("normal comment");
      
      // Verify truncated strings contain the first N characters
      expect(result[0].data[0].author).toBe("a".repeat(128));
      expect(result[0].data[0].createdBy).toBe("b".repeat(128));
      expect(result[0].data[0].comment).toBe("c".repeat(4096));
    });
  });

  describe("multiple facts", () => {
    it("should handle multiple fact types correctly", () => {
      const largeEnv = Array.from({ length: 600 }, (_, i) => `VAR${i}=value${i}`);
      const largeHistory = Array.from({ length: 1200 }, (_, i) => ({
        author: `author${i}`,
        createdBy: `RUN step${i}`,
      }));

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
      
      // containerConfig should be truncated
      expect(result[0].data.env).toHaveLength(500);
      expect(result[0].data.user).toBe("root"); // Unchanged
      
      // history should be truncated
      expect(result[1].data).toHaveLength(1000);
      
      // platform should be unchanged (no limits defined)
      expect(result[2]).toEqual(facts[2]);
    });

    it("should preserve fact structure and other properties", () => {
      const facts = [
        {
          type: "containerConfig",
          data: {
            env: Array.from({ length: 600 }, (_, i) => `VAR${i}=value${i}`),
          },
          metadata: { source: "dockerfile" },
          version: "1.0",
        },
      ];

      const result = truncateAdditionalFacts(facts);
      expect(result[0].type).toBe("containerConfig");
      expect(result[0].metadata).toEqual({ source: "dockerfile" });
      expect(result[0].version).toBe("1.0");
      expect(result[0].data.env).toHaveLength(500);
    });

    it("should selectively truncate only fields that exceed limits (mix and match)", () => {
      const longComment = "x".repeat(5000); // Exceeds 4096 limit
      const longUser = "y".repeat(2000); // Exceeds 1024 limit
      const normalEnv = ["VAR1=value1", "VAR2=value2"]; // Within 500 limit
      const normalAuthor = "normal author"; // Within 128 limit

      const facts = [
        {
          type: "containerConfig",
          data: {
            user: longUser, // Should be truncated to 1024
            env: normalEnv, // Should remain unchanged
            cmd: ["echo", "hello"], // Should remain unchanged
            workingDir: "/app", // Should remain unchanged
            stopSignal: "SIGTERM", // Should remain unchanged
          },
        },
        {
          type: "history",
          data: [
            {
              author: normalAuthor, // Should remain unchanged
              createdBy: "RUN apt-get update", // Should remain unchanged
              comment: longComment, // Should be truncated to 4096
              created: "2023-01-01T00:00:00Z", // Should remain unchanged
              emptyLayer: false, // Should remain unchanged
            },
            {
              author: "another author", // Should remain unchanged
              createdBy: "COPY . /app", // Should remain unchanged
              comment: "short comment", // Should remain unchanged
            },
          ],
        },
        {
          type: "platform",
          data: {
            os: "linux", // Should remain unchanged (no limits for platform)
            architecture: "amd64", // Should remain unchanged
          },
        },
      ];

      const result = truncateAdditionalFacts(facts);

      // Verify containerConfig: only user should be truncated
      expect(result[0].data.user).toHaveLength(1024);
      expect(result[0].data.user).toBe(longUser.substring(0, 1024));
      expect(result[0].data.env).toEqual(normalEnv); // Unchanged
      expect(result[0].data.cmd).toEqual(["echo", "hello"]); // Unchanged
      expect(result[0].data.workingDir).toBe("/app"); // Unchanged
      expect(result[0].data.stopSignal).toBe("SIGTERM"); // Unchanged

      // Verify history: only comment in first item should be truncated
      expect(result[1].data).toHaveLength(2); // Array length unchanged
      
      // First history item
      expect(result[1].data[0].author).toBe(normalAuthor); // Unchanged
      expect(result[1].data[0].createdBy).toBe("RUN apt-get update"); // Unchanged
      expect(result[1].data[0].comment).toHaveLength(4096); // Truncated
      expect(result[1].data[0].comment).toBe(longComment.substring(0, 4096));
      expect(result[1].data[0].created).toBe("2023-01-01T00:00:00Z"); // Unchanged
      expect(result[1].data[0].emptyLayer).toBe(false); // Unchanged
      
      // Second history item (all should remain unchanged)
      expect(result[1].data[1].author).toBe("another author");
      expect(result[1].data[1].createdBy).toBe("COPY . /app");
      expect(result[1].data[1].comment).toBe("short comment");

      // Verify platform: everything should remain unchanged
      expect(result[2]).toEqual(facts[2]);
    });
  });
});
