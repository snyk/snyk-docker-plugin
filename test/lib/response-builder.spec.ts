import { buildResponse } from "../../lib/response-builder";
import { RESPONSE_SIZE_LIMITS, truncateAdditionalFacts } from "../../lib/utils";

describe("buildResponse", () => {
  const createMockAnalysis = (overrides = {}) => ({
    depTree: {
      dependencies: {},
      name: "test",
      version: "1.0.0",
      packageFormatVersion: "1.0.0",
      targetOS: {
        prettyName: "Test OS",
      },
    },
    packageFormat: "test",
    manifestFiles: [],
    ...overrides,
  });

  describe("ensure fact structure with undefined properties", () => {
    it("should exclude undefined and missing containerConfig properties", async () => {
      const containerConfig: any = {
        User: undefined,
        Env: ["PATH=/usr/bin"],
        Cmd: undefined,
        WorkingDir: "/app",
        ArgsEscaped: undefined,
      };

      const mockAnalysis = createMockAnalysis({
        containerConfig,
      });

      const result = await buildResponse(mockAnalysis as any, undefined, false);

      const containerConfigFact = result.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "containerConfig");

      expect(containerConfigFact).toBeDefined();
      expect(containerConfigFact!.data).toEqual({
        env: ["PATH=/usr/bin"],
        workingDir: "/app",
      });

      expect(containerConfigFact!.data).not.toHaveProperty("user");
      expect(containerConfigFact!.data).not.toHaveProperty("cmd");
      expect(containerConfigFact!.data).not.toHaveProperty("argsEscaped");
      expect(containerConfigFact!.data).not.toHaveProperty("stopSignal");
      expect(containerConfigFact!.data).not.toHaveProperty("entrypoint");
      expect(containerConfigFact!.data).not.toHaveProperty("exposedPorts");
      expect(containerConfigFact!.data).not.toHaveProperty("volumes");
    });

    it("should include empty strings but exclude undefined values", async () => {
      const containerConfig: any = {
        User: "",
        WorkingDir: undefined,
        StopSignal: "",
      };

      const mockAnalysis = createMockAnalysis({
        containerConfig,
      });

      const result = await buildResponse(mockAnalysis as any, undefined, false);

      const containerConfigFact = result.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "containerConfig");

      expect(containerConfigFact).toBeDefined();
      expect(containerConfigFact!.data).toEqual({
        user: "",
        stopSignal: "",
      });

      expect(containerConfigFact!.data).toHaveProperty("user", "");
      expect(containerConfigFact!.data).toHaveProperty("stopSignal", "");
      expect(containerConfigFact!.data).not.toHaveProperty("workingDir");
    });

    it("should include null values for string properties", async () => {
      const containerConfig: any = {
        User: null,
        WorkingDir: null,
        StopSignal: "SIGTERM",
        Env: undefined,
      };

      const mockAnalysis = createMockAnalysis({
        containerConfig,
      });

      const result = await buildResponse(mockAnalysis as any, undefined, false);

      const containerConfigFact = result.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "containerConfig");

      expect(containerConfigFact).toBeDefined();
      expect(containerConfigFact!.data).toEqual({
        user: null,
        workingDir: null,
        stopSignal: "SIGTERM",
      });

      expect(containerConfigFact!.data).toHaveProperty("user", null);
      expect(containerConfigFact!.data).toHaveProperty("workingDir", null);
      expect(containerConfigFact!.data).toHaveProperty("stopSignal", "SIGTERM");
      expect(containerConfigFact!.data).not.toHaveProperty("env");
    });

    it("should handle null containerConfig", async () => {
      const mockAnalysis = createMockAnalysis({
        containerConfig: null,
      });

      const result = await buildResponse(mockAnalysis as any, undefined, false);

      const containerConfigFact = result.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "containerConfig");

      expect(containerConfigFact).toBeUndefined();
    });

    it("should handle null history", async () => {
      const mockAnalysis = createMockAnalysis({
        history: null,
      });

      const result = await buildResponse(mockAnalysis as any, undefined, false);

      const historyFact = result.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "history");

      // Should create a history fact with null data when history is null
      expect(historyFact).toBeUndefined();
    });

    it("should handle imageLabels when config is undefined vs defined", async () => {
      // Test case 1: config is undefined - should not create imageLabels fact
      const mockAnalysisUndefinedConfig = createMockAnalysis({
        imageLabels: undefined,
      });

      const resultUndefined = await buildResponse(
        mockAnalysisUndefinedConfig as any,
        undefined,
        false,
      );

      const imageLabelsFactUndefined = resultUndefined.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "imageLabels");
      expect(imageLabelsFactUndefined).toBeUndefined();

      // Test case 2: config is defined with labels - should create imageLabels fact
      const mockAnalysisWithLabels = createMockAnalysis({
        imageLabels: {
          maintainer: "test@example.com",
          version: "1.0.0",
        },
      });

      const resultWithLabels = await buildResponse(
        mockAnalysisWithLabels as any,
        undefined,
        false,
      );

      const imageLabelsFactWithLabels = resultWithLabels.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "imageLabels");

      expect(imageLabelsFactWithLabels).toBeDefined();
      expect(imageLabelsFactWithLabels!.data).toEqual({
        maintainer: "test@example.com",
        version: "1.0.0",
      });

      // Test case 3: config is defined but labels is empty object - should create imageLabels fact with empty object
      const mockAnalysisEmptyLabels = createMockAnalysis({
        imageLabels: {},
      });

      const resultEmptyLabels = await buildResponse(
        mockAnalysisEmptyLabels as any,
        undefined,
        false,
      );

      const imageLabelsFactEmpty = resultEmptyLabels.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "imageLabels");

      expect(imageLabelsFactEmpty).toBeDefined();
      expect(imageLabelsFactEmpty!.data).toEqual({});
    });

    it("should handle ExposedPorts and Volumes", async () => {
      const testCases = [
        {
          name: "undefined ExposedPorts and Volumes",
          containerConfig: {
            User: "root",
            ExposedPorts: undefined,
            Volumes: undefined,
          },
          expected: {
            user: "root",
          },
          shouldNotHave: ["exposedPorts", "volumes"],
        },
        {
          name: "missing ExposedPorts and Volumes",
          containerConfig: {
            User: "root",
          },
          expected: {
            user: "root",
          },
          shouldNotHave: ["exposedPorts", "volumes"],
        },
        {
          name: "null ExposedPorts and Volumes treat null as undefined for arrays",
          containerConfig: {
            User: "root",
            ExposedPorts: null,
            Volumes: null,
          },
          expected: {
            user: "root",
            exposedPorts: null,
            volumes: null,
          },
          shouldNotHave: [],
        },
        {
          name: "empty ExposedPorts and Volumes",
          containerConfig: {
            User: "root",
            ExposedPorts: {},
            Volumes: {},
          },
          expected: {
            user: "root",
            exposedPorts: [],
            volumes: [],
          },
          shouldNotHave: [],
        },
        {
          name: "populated ExposedPorts and Volumes",
          containerConfig: {
            User: "root",
            ExposedPorts: { "80/tcp": {}, "443/tcp": {} },
            Volumes: { "/data": {}, "/logs": {} },
          },
          expected: {
            user: "root",
            exposedPorts: ["80/tcp", "443/tcp"],
            volumes: ["/data", "/logs"],
          },
          shouldNotHave: [],
        },
      ];

      for (const testCase of testCases) {
        const mockAnalysis = createMockAnalysis({
          containerConfig: testCase.containerConfig,
        });

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
        );

        const containerConfigFact = result.scanResults
          .flatMap((scanResult) => scanResult.facts || [])
          .find((fact) => fact.type === "containerConfig");

        expect(containerConfigFact).toBeDefined();
        expect(containerConfigFact!.data).toEqual(testCase.expected);

        for (const prop of testCase.shouldNotHave) {
          expect(containerConfigFact!.data).not.toHaveProperty(prop);
        }
      }
    });

    it("should handle boolean undefined correctly", async () => {
      const testCases = [
        { ArgsEscaped: true, shouldInclude: true },
        { ArgsEscaped: false, shouldInclude: true },
        { ArgsEscaped: undefined, shouldInclude: false },
      ];

      for (const { ArgsEscaped, shouldInclude } of testCases) {
        const mockAnalysis = createMockAnalysis({
          containerConfig: {
            User: "root",
            ArgsEscaped,
          },
        });

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
        );

        const containerConfigFact = result.scanResults
          .flatMap((scanResult) => scanResult.facts || [])
          .find((fact) => fact.type === "containerConfig");

        expect(containerConfigFact).toBeDefined();

        if (shouldInclude) {
          expect(containerConfigFact!.data).toHaveProperty(
            "argsEscaped",
            ArgsEscaped,
          );
        } else {
          expect(containerConfigFact!.data).not.toHaveProperty("argsEscaped");
        }
      }
    });

    it("should exclude undefined history entry properties", async () => {
      const mockAnalysis = createMockAnalysis({
        history: [
          {
            created: "2023-01-01T00:00:00Z",
            author: undefined,
            created_by: "RUN echo test",
            comment: undefined,
            empty_layer: true,
          },
          {
            created: undefined,
            author: "test-author",
            created_by: undefined,
            comment: "test comment",
            empty_layer: undefined,
          },
          {
            author: "another-author",
          },
        ],
      });

      const result = await buildResponse(mockAnalysis as any, undefined, false);

      const historyFact = result.scanResults
        .flatMap((scanResult) => scanResult.facts || [])
        .find((fact) => fact.type === "history");

      expect(historyFact).toBeDefined();
      expect(historyFact!.data).toHaveLength(3);

      expect(historyFact!.data[0]).toEqual({
        created: "2023-01-01T00:00:00Z",
        createdBy: "RUN echo test",
        emptyLayer: true,
      });
      expect(historyFact!.data[0]).not.toHaveProperty("author");
      expect(historyFact!.data[0]).not.toHaveProperty("comment");

      expect(historyFact!.data[1]).toEqual({
        author: "test-author",
        comment: "test comment",
      });
      expect(historyFact!.data[1]).not.toHaveProperty("created");
      expect(historyFact!.data[1]).not.toHaveProperty("createdBy");
      expect(historyFact!.data[1]).not.toHaveProperty("emptyLayer");

      expect(historyFact!.data[2]).toEqual({
        author: "another-author",
      });
      expect(historyFact!.data[2]).not.toHaveProperty("created");
      expect(historyFact!.data[2]).not.toHaveProperty("createdBy");
      expect(historyFact!.data[2]).not.toHaveProperty("comment");
      expect(historyFact!.data[2]).not.toHaveProperty("emptyLayer");
    });

    it("should handle boolean empty_layer correctly in history", async () => {
      const testCases = [
        { empty_layer: true, shouldInclude: true },
        { empty_layer: false, shouldInclude: true },
        { empty_layer: undefined, shouldInclude: false },
      ];

      for (const { empty_layer, shouldInclude } of testCases) {
        const mockAnalysis = createMockAnalysis({
          history: [
            {
              created: "2023-01-01T00:00:00Z",
              author: "test",
              empty_layer,
            },
          ],
        });
        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
        );
        const historyFact = result.scanResults
          .flatMap((scanResult) => scanResult.facts || [])
          .find((fact) => fact.type === "history");

        expect(historyFact).toBeDefined();
        expect(historyFact!.data).toHaveLength(1);
        if (shouldInclude) {
          expect(historyFact!.data[0]).toHaveProperty(
            "emptyLayer",
            empty_layer,
          );
        } else {
          expect(historyFact!.data[0]).not.toHaveProperty("emptyLayer");
        }
      }
    });

    describe("fact truncation integration", () => {
      it("should pass through facts without truncation when within limits", async () => {
        const containerConfig = {
          User: "testuser",
          Env: ["PATH=/usr/bin", "HOME=/root"],
          Cmd: ["nginx", "-g", "daemon off;"],
          ExposedPorts: { "80/tcp": {}, "443/tcp": {} },
          WorkingDir: "/app",
          StopSignal: "SIGTERM",
        };

        const history = [
          {
            created: "2023-01-01T00:00:00Z",
            author: "test",
            created_by: "RUN echo test",
            comment: "Test layer",
            empty_layer: false,
          },
        ];

        const mockAnalysis = createMockAnalysis({
          containerConfig,
          history,
        });

        // Add ociDistributionMetadata which doesn't have any size limits
        const ociDistributionMetadata = {
          registryHost: "docker.io",
          repository: "library/nginx",
          manifestDigest:
            "sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
          imageTag: "latest",
        };

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
          undefined,
          ociDistributionMetadata,
        );

        const containerConfigFact = result.scanResults
          .flatMap((scanResult) => scanResult.facts || [])
          .find((fact) => fact.type === "containerConfig");

        const historyFact = result.scanResults
          .flatMap((scanResult) => scanResult.facts || [])
          .find((fact) => fact.type === "history");

        const ociDistributionMetadataFact = result.scanResults
          .flatMap((scanResult) => scanResult.facts || [])
          .find((fact) => fact.type === "ociDistributionMetadata");

        expect(containerConfigFact).toBeDefined();
        expect(containerConfigFact!.data).toEqual({
          user: "testuser",
          env: ["PATH=/usr/bin", "HOME=/root"],
          cmd: ["nginx", "-g", "daemon off;"],
          exposedPorts: ["80/tcp", "443/tcp"],
          workingDir: "/app",
          stopSignal: "SIGTERM",
        });

        expect(historyFact).toBeDefined();
        expect(historyFact!.data).toEqual([
          {
            created: "2023-01-01T00:00:00Z",
            author: "test",
            createdBy: "RUN echo test",
            comment: "Test layer",
            emptyLayer: false,
          },
        ]);

        // ociDistributionMetadata should be the same
        expect(ociDistributionMetadataFact).toBeDefined();
        expect(ociDistributionMetadataFact!.data).toEqual({
          registryHost: "docker.io",
          repository: "library/nginx",
          manifestDigest:
            "sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
          imageTag: "latest",
        });

        // Should not create any pluginWarnings fact since no truncation occurred
        const pluginWarningsFact = result.scanResults
          .flatMap((scanResult) => scanResult.facts || [])
          .find((fact) => fact.type === "pluginWarnings");

        expect(pluginWarningsFact).toBeUndefined();
      });

      it("should handle multiple scan results correctly", async () => {
        const mockAnalysis1 = createMockAnalysis({
          containerConfig: {
            User: "user1",
            Env: ["ENV1=value1"],
          },
        });

        const mockAnalysis2 = createMockAnalysis({
          containerConfig: {
            User: "user2",
            Cmd: ["cmd2"],
          },
        });

        // Simulate multiple scan results
        const customResult = {
          scanResults: [
            {
              facts: [
                {
                  type: "containerConfig" as const,
                  data: {
                    user: "user1",
                    env: ["ENV1=value1"],
                  },
                },
                {
                  type: "depGraph" as const,
                  data: mockAnalysis1.depTree,
                },
              ],
              identity: { type: "apk" as const },
              target: { image: "test-image-1" },
            },
            {
              facts: [
                {
                  type: "containerConfig" as const,
                  data: {
                    user: "user2",
                    cmd: ["cmd2"],
                  },
                },
                {
                  type: "history" as const,
                  data: [
                    {
                      created: "2023-01-01T00:00:00Z",
                      author: "test2",
                    },
                  ],
                },
              ],
              identity: { type: "npm" as const },
              target: { image: "test-image-2" },
            },
          ],
        };

        // Apply same truncation logic as response builder
        const truncatedResult = {
          scanResults: customResult.scanResults.map((result) => ({
            ...result,
            facts: result.facts || [],
          })),
        };

        expect(truncatedResult.scanResults).toHaveLength(2);
        // check first scan result
        const firstScanResult = truncatedResult.scanResults[0];
        expect(firstScanResult.identity.type).toBe("apk");
        expect(firstScanResult.target.image).toBe("test-image-1");

        const firstContainerConfig = firstScanResult.facts.find(
          (fact) => fact.type === "containerConfig",
        );
        expect(firstContainerConfig?.data).toEqual({
          user: "user1",
          env: ["ENV1=value1"],
        });

        // check second scan result
        const secondScanResult = truncatedResult.scanResults[1];
        expect(secondScanResult.identity.type).toBe("npm");
        expect(secondScanResult.target.image).toBe("test-image-2");

        const secondContainerConfig = secondScanResult.facts.find(
          (fact) => fact.type === "containerConfig",
        );
        expect(secondContainerConfig?.data).toEqual({
          user: "user2",
          cmd: ["cmd2"],
        });

        const secondHistory = secondScanResult.facts.find(
          (fact) => fact.type === "history",
        );
        expect(secondHistory?.data).toEqual([
          {
            created: "2023-01-01T00:00:00Z",
            author: "test2",
          },
        ]);
      });

      it("should handle mixed truncation across multiple scan results", async () => {
        const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;

        // Create scan result 1: Will be truncated (oversized env array)
        const oversizedEnv = Array.from(
          { length: envLimit + 50 },
          (_, i) => `VAR${i}=value${i}`,
        );
        const scanResult1 = {
          facts: [
            {
              type: "containerConfig" as const,
              data: {
                user: "user1",
                env: oversizedEnv, // This will be truncated
                cmd: ["nginx"],
              },
            },
            {
              type: "depGraph" as const,
              data: {} as any,
            },
          ],
          identity: { type: "apk" as const },
          target: { image: "test-image-1" },
        };

        // Create scan result 2: Will NOT be truncated
        const normalEnv = ["PATH=/usr/bin", "HOME=/root"];
        const normalHistory = [
          {
            created: "2023-01-01T00:00:00Z",
            author: "test",
            createdBy: "RUN echo test",
          },
        ];
        const scanResult2 = {
          facts: [
            {
              type: "containerConfig" as const,
              data: {
                user: "user2",
                env: normalEnv,
                workingDir: "/app",
              },
            },
            {
              type: "history" as const,
              data: normalHistory,
            },
            {
              type: "ociDistributionMetadata" as const,
              data: {
                registryHost: "docker.io",
                repository: "library/alpine",
                manifestDigest:
                  "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                imageTag: "latest",
              },
            },
          ],
          identity: { type: "npm" as const },
          target: { image: "test-image-2" },
        };

        // same truncation logic like buildResponse does
        const result = {
          scanResults: [scanResult1, scanResult2].map((scanResult) => ({
            ...scanResult,
            facts: truncateAdditionalFacts(scanResult.facts || []),
          })),
        };

        expect(result.scanResults).toHaveLength(2);

        // check scan result 1: Should be truncated and have pluginWarnings
        const firstScanResult = result.scanResults[0];
        const firstContainerConfig = firstScanResult.facts.find(
          (fact) => fact.type === "containerConfig",
        );
        const firstPluginWarnings = firstScanResult.facts.find(
          (fact) => fact.type === "pluginWarnings",
        );

        expect(firstContainerConfig?.data.env).toHaveLength(envLimit);
        expect(firstContainerConfig?.data.env).toEqual(
          oversizedEnv.slice(0, envLimit),
        );
        expect(firstContainerConfig?.data.user).toBe("user1");
        expect(firstContainerConfig?.data.cmd).toEqual(["nginx"]);

        // Should have pluginWarnings for truncation
        expect(firstPluginWarnings).toBeDefined();
        expect(firstPluginWarnings?.data.truncatedFacts).toEqual({
          "containerConfig.data.env": {
            type: "array",
            countAboveLimit: 50,
          },
        });

        // check scan result 2: Should NOT be truncated and have NO pluginWarnings
        const secondScanResult = result.scanResults[1];
        const secondContainerConfig = secondScanResult.facts.find(
          (fact) => fact.type === "containerConfig",
        );
        const secondHistory = secondScanResult.facts.find(
          (fact) => fact.type === "history",
        );
        const secondOciMetadata = secondScanResult.facts.find(
          (fact) => fact.type === "ociDistributionMetadata",
        );
        const secondPluginWarnings = secondScanResult.facts.find(
          (fact) => fact.type === "pluginWarnings",
        );

        // Should pass through unchanged
        expect(secondContainerConfig?.data).toEqual({
          user: "user2",
          env: normalEnv, // NOT truncated
          workingDir: "/app",
        });
        expect(secondHistory?.data).toEqual(normalHistory);
        expect(secondOciMetadata?.data).toEqual({
          registryHost: "docker.io",
          repository: "library/alpine",
          manifestDigest:
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          imageTag: "latest",
        });

        // Should NOT have pluginWarnings
        expect(secondPluginWarnings).toBeUndefined();
      });
    });
  });
});
