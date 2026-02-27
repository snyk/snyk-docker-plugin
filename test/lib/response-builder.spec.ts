import { buildResponse } from "../../lib/response-builder";
import { RESPONSE_SIZE_LIMITS } from "../../lib/utils";

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
        platform: "linux/amd64",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        ["test-image:v1.0"],
        undefined,
        { "target-reference": "undefined-props-test" },
      );

      expect(result.scanResults).toHaveLength(1);
      const mainScanResult = result.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResult).toHaveProperty("facts");
      expect(mainScanResult).toHaveProperty("target");
      expect(mainScanResult).toHaveProperty("identity");
      expect(mainScanResult).toHaveProperty("targetReference");
      expect(mainScanResult).not.toHaveProperty("name");

      expect(mainScanResult.target).toEqual({ image: "test" });
      expect(mainScanResult.identity).toEqual({
        type: "test",
        args: { platform: "linux/amd64" },
      });
      expect(mainScanResult.targetReference).toBe("undefined-props-test");

      const containerConfigFact = mainScanResult.facts?.find(
        (fact) => fact.type === "containerConfig",
      );

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
        platform: "linux/arm64",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        ["test-image:empty-strings"],
        undefined,
        { "target-reference": "empty-strings-test" },
      );

      expect(result.scanResults).toHaveLength(1);
      const mainScanResult = result.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResult).toHaveProperty("facts");
      expect(mainScanResult).toHaveProperty("target");
      expect(mainScanResult).toHaveProperty("identity");
      expect(mainScanResult).toHaveProperty("targetReference");
      expect(mainScanResult).not.toHaveProperty("name");

      expect(mainScanResult.target).toEqual({ image: "test" });
      expect(mainScanResult.identity).toEqual({
        type: "test",
        args: { platform: "linux/arm64" },
      });
      expect(mainScanResult.targetReference).toBe("empty-strings-test");

      const containerConfigFact = mainScanResult.facts?.find(
        (fact) => fact.type === "containerConfig",
      );

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
        platform: "linux/s390x",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        ["test-image:null-values"],
        undefined,
        { "target-reference": "null-values-test" },
      );

      expect(result.scanResults).toHaveLength(1);
      const mainScanResult = result.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResult).toHaveProperty("facts");
      expect(mainScanResult).toHaveProperty("target");
      expect(mainScanResult).toHaveProperty("identity");
      expect(mainScanResult).toHaveProperty("targetReference");
      expect(mainScanResult).not.toHaveProperty("name");

      expect(mainScanResult.target).toEqual({ image: "test" });
      expect(mainScanResult.identity).toEqual({
        type: "test",
        args: { platform: "linux/s390x" },
      });
      expect(mainScanResult.targetReference).toBe("null-values-test");

      const containerConfigFact = mainScanResult.facts?.find(
        (fact) => fact.type === "containerConfig",
      );

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

    it("null containerConfig should produce no fact", async () => {
      const mockAnalysis = createMockAnalysis({
        containerConfig: null,
        platform: "linux/ppc64le",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        ["test-image:null-config"],
        undefined,
        { "target-reference": "null-config-test" },
      );

      expect(result.scanResults).toHaveLength(1);
      const mainScanResult = result.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResult).toHaveProperty("facts");
      expect(mainScanResult).toHaveProperty("target");
      expect(mainScanResult).toHaveProperty("identity");
      expect(mainScanResult).toHaveProperty("targetReference");
      expect(mainScanResult).not.toHaveProperty("name");

      expect(mainScanResult.target).toEqual({ image: "test" });
      expect(mainScanResult.identity).toEqual({
        type: "test",
        args: { platform: "linux/ppc64le" },
      });
      expect(mainScanResult.targetReference).toBe("null-config-test");

      const containerConfigFact = mainScanResult.facts?.find(
        (fact) => fact.type === "containerConfig",
      );
      // should be undefined if the entire fact is null
      expect(containerConfigFact).toBeUndefined();
    });

    it("null history should produce no fact", async () => {
      const mockAnalysis = createMockAnalysis({
        history: null,
        platform: "linux/riscv64",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        ["test-image:null-history"],
        undefined,
        { "target-reference": "null-history-test" },
      );

      expect(result.scanResults).toHaveLength(1);
      const mainScanResult = result.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResult).toHaveProperty("facts");
      expect(mainScanResult).toHaveProperty("target");
      expect(mainScanResult).toHaveProperty("identity");
      expect(mainScanResult).toHaveProperty("targetReference");
      expect(mainScanResult).not.toHaveProperty("name");

      expect(mainScanResult.target).toEqual({ image: "test" });
      expect(mainScanResult.identity).toEqual({
        type: "test",
        args: { platform: "linux/riscv64" },
      });
      expect(mainScanResult.targetReference).toBe("null-history-test");

      const historyFact = mainScanResult.facts?.find(
        (fact) => fact.type === "history",
      );
      // should be undefined if the entire fact is null
      expect(historyFact).toBeUndefined();
    });

    it("should handle imageLabels when config is undefined vs defined", async () => {
      // Test case 1: config and labels are both undefined - should not create imageLabels fact
      const mockAnalysisUndefinedConfig = createMockAnalysis({
        imageLabels: undefined,
        platform: "linux/386",
      });

      const resultUndefined = await buildResponse(
        mockAnalysisUndefinedConfig as any,
        undefined,
        false,
        ["test-image:undefined-labels"],
        undefined,
        { "target-reference": "undefined-labels-test" },
      );

      expect(resultUndefined.scanResults).toHaveLength(1);
      const mainScanResultUndefined = resultUndefined.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResultUndefined).toHaveProperty("facts");
      expect(mainScanResultUndefined).toHaveProperty("target");
      expect(mainScanResultUndefined).toHaveProperty("identity");
      expect(mainScanResultUndefined).toHaveProperty("targetReference");
      expect(mainScanResultUndefined).not.toHaveProperty("name");

      expect(mainScanResultUndefined.target).toEqual({ image: "test" });
      expect(mainScanResultUndefined.identity).toEqual({
        type: "test",
        args: { platform: "linux/386" },
      });
      expect(mainScanResultUndefined.targetReference).toBe(
        "undefined-labels-test",
      );

      const imageLabelsFactUndefined = mainScanResultUndefined.facts?.find(
        (fact) => fact.type === "imageLabels",
      );
      expect(imageLabelsFactUndefined).toBeUndefined();

      // Test case 2: config is defined with labels - should create imageLabels fact
      const mockAnalysisWithLabels = createMockAnalysis({
        imageLabels: {
          maintainer: "test@example.com",
          version: "1.0.0",
        },
        platform: "linux/mips64le",
      });

      const resultWithLabels = await buildResponse(
        mockAnalysisWithLabels as any,
        undefined,
        false,
        ["test-image:with-labels"],
        undefined,
        { "target-reference": "with-labels-test" },
      );

      expect(resultWithLabels.scanResults).toHaveLength(1);
      const mainScanResultWithLabels = resultWithLabels.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResultWithLabels.target).toEqual({ image: "test" });
      expect(mainScanResultWithLabels.identity).toEqual({
        type: "test",
        args: { platform: "linux/mips64le" },
      });
      expect(mainScanResultWithLabels.targetReference).toBe("with-labels-test");

      const imageLabelsFactWithLabels = mainScanResultWithLabels.facts?.find(
        (fact) => fact.type === "imageLabels",
      );

      expect(imageLabelsFactWithLabels).toBeDefined();
      expect(imageLabelsFactWithLabels!.data).toEqual({
        maintainer: "test@example.com",
        version: "1.0.0",
      });

      // Test case 3: config is defined but labels is empty object - should create imageLabels fact with empty object
      const mockAnalysisEmptyLabels = createMockAnalysis({
        imageLabels: {},
        platform: "linux/mips",
      });

      const resultEmptyLabels = await buildResponse(
        mockAnalysisEmptyLabels as any,
        undefined,
        false,
        ["test-image:empty-labels"],
        undefined,
        { "target-reference": "empty-labels-test" },
      );

      expect(resultEmptyLabels.scanResults).toHaveLength(1);
      const mainScanResultEmptyLabels = resultEmptyLabels.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResultEmptyLabels.target).toEqual({ image: "test" });
      expect(mainScanResultEmptyLabels.identity).toEqual({
        type: "test",
        args: { platform: "linux/mips" },
      });
      expect(mainScanResultEmptyLabels.targetReference).toBe(
        "empty-labels-test",
      );

      const imageLabelsFactEmpty = mainScanResultEmptyLabels.facts?.find(
        (fact) => fact.type === "imageLabels",
      );

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
          name: "null ExposedPorts and Volumes shoudl be assigned null",
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
          name: "empty ExposedPorts and Volumes should be empty arrays",
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
          platform: "linux/arm64",
        });

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
          [`test-image:${testCase.name.replace(/\s+/g, "-").toLowerCase()}`],
          undefined,
          {
            "target-reference": `${testCase.name
              .replace(/\s+/g, "-")
              .toLowerCase()}-test`,
          },
        );

        expect(result.scanResults).toHaveLength(1);
        const mainScanResult = result.scanResults[0];

        // Verify scan result structure is preserved
        expect(mainScanResult).toHaveProperty("facts");
        expect(mainScanResult).toHaveProperty("target");
        expect(mainScanResult).toHaveProperty("identity");
        expect(mainScanResult).toHaveProperty("targetReference");
        expect(mainScanResult).not.toHaveProperty("name");

        expect(mainScanResult.target).toEqual({ image: "test" });
        expect(mainScanResult.identity).toEqual({
          type: "test",
          args: { platform: "linux/arm64" },
        });
        expect(mainScanResult.targetReference).toBe(
          `${testCase.name.replace(/\s+/g, "-").toLowerCase()}-test`,
        );

        const containerConfigFact = mainScanResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );

        expect(containerConfigFact).toBeDefined();
        expect(containerConfigFact!.data).toEqual(testCase.expected);

        for (const prop of testCase.shouldNotHave) {
          expect(containerConfigFact!.data).not.toHaveProperty(prop);
        }
      }
    });

    it("should handle boolean undefined and null correctly", async () => {
      const testCases = [
        { ArgsEscaped: true, shouldInclude: true },
        { ArgsEscaped: false, shouldInclude: true },
        { ArgsEscaped: undefined, shouldInclude: false },
        { ArgsEscaped: null, shouldInclude: true },
      ];

      for (const { ArgsEscaped, shouldInclude } of testCases) {
        const mockAnalysis = createMockAnalysis({
          containerConfig: {
            User: "root",
            ArgsEscaped,
          },
          platform: "linux/amd64",
        });

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
          [`test-image:boolean-${ArgsEscaped}`],
          undefined,
          { "target-reference": `boolean-${ArgsEscaped}-test` },
        );

        expect(result.scanResults).toHaveLength(1);
        const mainScanResult = result.scanResults[0];

        // Verify scan result structure is preserved
        expect(mainScanResult).toHaveProperty("facts");
        expect(mainScanResult).toHaveProperty("target");
        expect(mainScanResult).toHaveProperty("identity");
        expect(mainScanResult).toHaveProperty("targetReference");
        expect(mainScanResult).not.toHaveProperty("name");

        expect(mainScanResult.target).toEqual({ image: "test" });
        expect(mainScanResult.identity).toEqual({
          type: "test",
          args: { platform: "linux/amd64" },
        });
        expect(mainScanResult.targetReference).toBe(
          `boolean-${ArgsEscaped}-test`,
        );

        const containerConfigFact = mainScanResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );

        expect(containerConfigFact).toBeDefined();

        if (shouldInclude) {
          expect(containerConfigFact!.data).toHaveProperty("argsEscaped");
          expect(containerConfigFact!.data.argsEscaped).toBe(ArgsEscaped);
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
        platform: "linux/sparc64",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        ["test-image:undefined-history-props"],
        undefined,
        { "target-reference": "undefined-history-props-test" },
      );

      expect(result.scanResults).toHaveLength(1);
      const mainScanResult = result.scanResults[0];

      // Verify scan result structure is preserved
      expect(mainScanResult).toHaveProperty("facts");
      expect(mainScanResult).toHaveProperty("target");
      expect(mainScanResult).toHaveProperty("identity");
      expect(mainScanResult).toHaveProperty("targetReference");
      expect(mainScanResult).not.toHaveProperty("name");

      expect(mainScanResult.target).toEqual({ image: "test" });
      expect(mainScanResult.identity).toEqual({
        type: "test",
        args: { platform: "linux/sparc64" },
      });
      expect(mainScanResult.targetReference).toBe(
        "undefined-history-props-test",
      );

      const historyFact = mainScanResult.facts?.find(
        (fact) => fact.type === "history",
      );

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
        { empty_layer: null, shouldInclude: true },
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
          platform: "linux/s390x",
        });
        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
          [`test-image:empty-layer-${empty_layer}`],
          undefined,
          { "target-reference": `empty-layer-${empty_layer}-test` },
        );

        expect(result.scanResults).toHaveLength(1);
        const mainScanResult = result.scanResults[0];

        // Verify scan result structure is preserved
        expect(mainScanResult).toHaveProperty("facts");
        expect(mainScanResult).toHaveProperty("target");
        expect(mainScanResult).toHaveProperty("identity");
        expect(mainScanResult).toHaveProperty("targetReference");
        expect(mainScanResult).not.toHaveProperty("name");

        expect(mainScanResult.target).toEqual({ image: "test" });
        expect(mainScanResult.identity).toEqual({
          type: "test",
          args: { platform: "linux/s390x" },
        });
        expect(mainScanResult.targetReference).toBe(
          `empty-layer-${empty_layer}-test`,
        );

        const historyFact = mainScanResult.facts?.find(
          (fact) => fact.type === "history",
        );

        expect(historyFact).toBeDefined();
        expect(historyFact!.data).toHaveLength(1);
        if (shouldInclude) {
          expect(historyFact!.data[0]).toHaveProperty("emptyLayer");
          expect(historyFact!.data[0].emptyLayer).toBe(empty_layer);
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
          platform: "linux/amd64",
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
          ["test-image:v1.0"],
          ociDistributionMetadata,
          { "target-reference": "test-branch" },
        );

        expect(result.scanResults).toHaveLength(1);
        const mainScanResult = result.scanResults[0];

        // Verify scan result structure is preserved
        expect(mainScanResult).toHaveProperty("facts");
        expect(mainScanResult).toHaveProperty("target");
        expect(mainScanResult).toHaveProperty("identity");
        expect(mainScanResult).toHaveProperty("targetReference");
        expect(mainScanResult).not.toHaveProperty("name");

        expect(mainScanResult.target).toEqual({ image: "test" });
        expect(mainScanResult.identity).toEqual({
          type: "test",
          args: { platform: "linux/amd64" },
        });
        expect(mainScanResult.targetReference).toBe("test-branch");

        const containerConfigFact = mainScanResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );

        const historyFact = mainScanResult.facts?.find(
          (fact) => fact.type === "history",
        );

        const ociDistributionMetadataFact = mainScanResult.facts?.find(
          (fact) => fact.type === "ociDistributionMetadata",
        );

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
        const pluginWarningsFact = mainScanResult.facts?.find(
          (fact) => fact.type === "pluginWarnings",
        );

        expect(pluginWarningsFact).toBeUndefined();
      });

      it("should handle multiple scan results correctly with no truncation", async () => {
        // Create mock analysis to get multiple scan results
        const mockAnalysis = createMockAnalysis({
          containerConfig: {
            User: "mainuser",
            Env: ["MAIN_ENV=value"],
          },
          platform: "linux/amd64",
          applicationDependenciesScanResults: [
            {
              facts: [
                {
                  type: "depGraph" as const,
                  data: {} as any,
                },
                {
                  type: "testedFiles" as const,
                  data: "/app/package.json",
                },
                {
                  type: "containerConfig" as const,
                  data: {
                    user: "npmuser",
                    env: ["NODE_ENV=production", "PORT=3000"],
                    cmd: ["node", "server.js"],
                    workingDir: "/app",
                  },
                },
                {
                  type: "history" as const,
                  data: [
                    {
                      created: "2023-01-01T10:00:00Z",
                      author: "npm-builder",
                      createdBy: "RUN npm install",
                      comment: "Install npm dependencies",
                    },
                  ],
                },
              ],
              identity: { type: "npm" },
              target: { image: "test-app" },
            },
            {
              facts: [
                {
                  type: "depGraph" as const,
                  data: {} as any,
                },
                {
                  type: "testedFiles" as const,
                  data: "/app/requirements.txt",
                },
                {
                  type: "containerConfig" as const, // wouldn't be in application project, but testing to make sure for future truncation rules
                  data: {
                    user: "pythonuser",
                    env: ["PYTHONPATH=/app", "DEBUG=false"],
                    entrypoint: ["python", "main.py"],
                    workingDir: "/app",
                  },
                },
                {
                  type: "history" as const, // wouldn't be in application project, but testing to make sure for future truncation rules
                  data: [
                    {
                      created: "2023-01-01T11:00:00Z",
                      author: "python-builder",
                      createdBy: "RUN pip install -r requirements.txt",
                      comment: "Install Python dependencies",
                    },
                    {
                      created: "2023-01-01T11:30:00Z",
                      author: "python-builder",
                      createdBy: "COPY . /app",
                      comment: "Copy application code",
                    },
                  ],
                },
              ],
              identity: { type: "pip" },
              target: { image: "test-app" },
            },
          ],
        });

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
          ["test-image:latest"],
          undefined,
          { "target-reference": "multi-test-branch" },
        );

        // Should have 3 scan results: 1 main + 2 application dependency results
        expect(result.scanResults).toHaveLength(3);

        // Verify main scan result structure and identity
        const mainScanResult = result.scanResults[0];
        expect(mainScanResult).toHaveProperty("facts");
        expect(mainScanResult).toHaveProperty("target");
        expect(mainScanResult).toHaveProperty("identity");
        expect(mainScanResult).toHaveProperty("targetReference");
        expect(mainScanResult).not.toHaveProperty("name");

        expect(mainScanResult.target).toEqual({ image: "test" });
        expect(mainScanResult.identity).toEqual({
          type: "test",
          args: { platform: "linux/amd64" },
        });
        expect(mainScanResult.targetReference).toBe("multi-test-branch");
        const mainContainerConfig = mainScanResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );
        expect(mainContainerConfig?.data).toEqual({
          user: "mainuser",
          env: ["MAIN_ENV=value"],
        });

        // Verify first application dependency scan result structure and identity
        const firstAppResult = result.scanResults[1];
        expect(firstAppResult).toHaveProperty("facts");
        expect(firstAppResult).toHaveProperty("target");
        expect(firstAppResult).toHaveProperty("identity");
        expect(firstAppResult).toHaveProperty("targetReference");
        expect(firstAppResult).not.toHaveProperty("name"); // No name in original

        expect(firstAppResult.target).toEqual({ image: "test" }); // Overridden by buildResponse
        expect(firstAppResult.identity).toEqual({
          type: "npm",
          args: undefined,
        });
        expect(firstAppResult.targetReference).toBe("multi-test-branch"); // Overridden by options
        const firstTestedFiles = firstAppResult.facts?.find(
          (fact) => fact.type === "testedFiles",
        );
        const firstAppContainerConfig = firstAppResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );
        const firstAppHistory = firstAppResult.facts?.find(
          (fact) => fact.type === "history",
        );

        expect(firstTestedFiles?.data).toBe("/app/package.json");
        expect(firstAppContainerConfig?.data).toEqual({
          user: "npmuser",
          env: ["NODE_ENV=production", "PORT=3000"],
          cmd: ["node", "server.js"],
          workingDir: "/app",
        });
        expect(firstAppHistory?.data).toEqual([
          {
            created: "2023-01-01T10:00:00Z",
            author: "npm-builder",
            createdBy: "RUN npm install",
            comment: "Install npm dependencies",
          },
        ]);

        // Verify second application dependency scan result structure and identity
        const secondAppResult = result.scanResults[2];
        expect(secondAppResult).toHaveProperty("facts");
        expect(secondAppResult).toHaveProperty("target");
        expect(secondAppResult).toHaveProperty("identity");
        expect(secondAppResult).toHaveProperty("targetReference");
        expect(secondAppResult).not.toHaveProperty("name"); // No name in original

        expect(secondAppResult.target).toEqual({ image: "test" }); // Overridden by buildResponse
        expect(secondAppResult.identity).toEqual({
          type: "pip",
          args: undefined,
        });
        expect(secondAppResult.targetReference).toBe("multi-test-branch"); // Overridden by options
        const secondTestedFiles = secondAppResult.facts?.find(
          (fact) => fact.type === "testedFiles",
        );
        const secondAppContainerConfig = secondAppResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );
        const secondAppHistory = secondAppResult.facts?.find(
          (fact) => fact.type === "history",
        );

        expect(secondTestedFiles?.data).toBe("/app/requirements.txt");
        expect(secondAppContainerConfig?.data).toEqual({
          user: "pythonuser",
          env: ["PYTHONPATH=/app", "DEBUG=false"],
          entrypoint: ["python", "main.py"],
          workingDir: "/app",
        });
        expect(secondAppHistory?.data).toEqual([
          {
            created: "2023-01-01T11:00:00Z",
            author: "python-builder",
            createdBy: "RUN pip install -r requirements.txt",
            comment: "Install Python dependencies",
          },
          {
            created: "2023-01-01T11:30:00Z",
            author: "python-builder",
            createdBy: "COPY . /app",
            comment: "Copy application code",
          },
        ]);

        // Verify NO pluginWarnings facts in any scan result (no truncation occurred)
        const mainPluginWarnings = result.scanResults[0].facts?.find(
          (fact) => fact.type === "pluginWarnings",
        );
        const firstAppPluginWarnings = result.scanResults[1].facts?.find(
          (fact) => fact.type === "pluginWarnings",
        );
        const secondAppPluginWarnings = result.scanResults[2].facts?.find(
          (fact) => fact.type === "pluginWarnings",
        );
        expect(mainPluginWarnings).toBeUndefined();
        expect(firstAppPluginWarnings).toBeUndefined();
        expect(secondAppPluginWarnings).toBeUndefined();
      });

      it("should handle mixed truncation across multiple scan results", async () => {
        const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;
        const oversizedEnv = Array.from(
          { length: envLimit + 50 },
          (_, i) => `VAR${i}=value${i}`,
        );
        const normalHistory = [
          {
            created: "2023-01-01T00:00:00Z",
            author: "test",
            created_by: "RUN echo test",
          },
        ];
        // fact with no truncation rules
        const ociDistributionMetadata = {
          registryHost: "docker.io",
          repository: "library/alpine",
          manifestDigest:
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          imageTag: "latest",
        };

        const mockAnalysis = createMockAnalysis({
          containerConfig: {
            User: "mainuser",
            Env: oversizedEnv, // This will be truncated in main scan result
            Cmd: ["nginx"],
          },
          history: normalHistory,
          platform: "linux/amd64",
          applicationDependenciesScanResults: [
            {
              facts: [
                {
                  type: "depGraph" as const,
                  data: {} as any,
                },
                {
                  type: "containerConfig" as const, // this won't be in an application project, but testing for future functionality
                  data: {
                    user: "appuser",
                    env: oversizedEnv,
                    workingDir: "/app",
                  },
                },
              ],
              identity: { type: "npm" },
              target: { image: "test-app" },
            },
          ],
        });

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
          ["test-image:mixed"],
          ociDistributionMetadata,
          { "target-reference": "mixed-truncation-branch" },
        );

        // Should have 2 scan results: 1 main + 1 application dependency result
        expect(result.scanResults).toHaveLength(2);

        // Verify main scan result structure is preserved despite truncation (facts are modified, other properties unchanged)
        const mainScanResult = result.scanResults[0];
        expect(mainScanResult).toHaveProperty("facts");
        expect(mainScanResult).toHaveProperty("target");
        expect(mainScanResult).toHaveProperty("identity");
        expect(mainScanResult).toHaveProperty("targetReference");
        expect(mainScanResult).not.toHaveProperty("name");

        expect(mainScanResult.target).toEqual({ image: "test" });
        expect(mainScanResult.identity).toEqual({
          type: "test",
          args: { platform: "linux/amd64" },
        });
        expect(mainScanResult.targetReference).toBe("mixed-truncation-branch");
        const mainContainerConfig = mainScanResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );
        const mainPluginWarnings = mainScanResult.facts?.find(
          (fact) => fact.type === "pluginWarnings",
        );
        const mainHistory = mainScanResult.facts?.find(
          (fact) => fact.type === "history",
        );
        const mainOciMetadata = mainScanResult.facts?.find(
          (fact) => fact.type === "ociDistributionMetadata",
        );

        expect(mainContainerConfig?.data.env).toHaveLength(envLimit);
        expect(mainContainerConfig?.data.env).toEqual(
          oversizedEnv.slice(0, envLimit),
        );
        expect(mainContainerConfig?.data.user).toBe("mainuser");
        expect(mainContainerConfig?.data.cmd).toEqual(["nginx"]);

        // Should have pluginWarnings for truncation
        expect(mainPluginWarnings).toBeDefined();
        expect(mainPluginWarnings?.data.truncatedFacts).toEqual({
          "containerConfig.data.env": {
            type: "array",
            countAboveLimit: 50,
          },
        });

        // Should have history and ociDistributionMetadata in main scan result
        expect(mainHistory?.data).toEqual([
          {
            created: "2023-01-01T00:00:00Z",
            author: "test",
            createdBy: "RUN echo test",
          },
        ]);
        expect(mainOciMetadata?.data).toEqual({
          registryHost: "docker.io",
          repository: "library/alpine",
          manifestDigest:
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          imageTag: "latest",
        });

        // Verify application dependency scan result structure is preserved despite truncation (facts are modified, other properties unchanged)
        const appScanResult = result.scanResults[1];
        expect(appScanResult).toHaveProperty("facts");
        expect(appScanResult).toHaveProperty("target");
        expect(appScanResult).toHaveProperty("identity");
        expect(appScanResult).toHaveProperty("targetReference");
        expect(appScanResult).not.toHaveProperty("name"); // No name in original

        expect(appScanResult.target).toEqual({ image: "test" }); // Overridden by buildResponse
        expect(appScanResult.identity).toEqual({
          type: "npm",
          args: undefined,
        });
        expect(appScanResult.targetReference).toBe("mixed-truncation-branch"); // Overridden by options
        const appContainerConfig = appScanResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );
        const appOciMetadata = appScanResult.facts?.find(
          (fact) => fact.type === "ociDistributionMetadata",
        );
        const appPluginWarnings = appScanResult.facts?.find(
          (fact) => fact.type === "pluginWarnings",
        );

        expect(appContainerConfig?.data.env).toHaveLength(envLimit);
        expect(appContainerConfig?.data.env).toEqual(
          oversizedEnv.slice(0, envLimit),
        );
        expect(appContainerConfig?.data.user).toBe("appuser");
        expect(appContainerConfig?.data.workingDir).toBe("/app");

        expect(appOciMetadata?.data).toEqual({
          registryHost: "docker.io",
          repository: "library/alpine",
          manifestDigest:
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          imageTag: "latest",
        });

        // Should ALSO have pluginWarnings for truncation in app scan result
        expect(appPluginWarnings).toBeDefined();
        expect(appPluginWarnings?.data.truncatedFacts).toEqual({
          "containerConfig.data.env": {
            type: "array",
            countAboveLimit: 50,
          },
        });
      });

      it("should preserve scan result structure and only modify facts", async () => {
        // Main scan result gets: facts, target, identity, targetReference (from options)
        // Application scan results preserve: facts, identity, name but get target and targetReference overridden by buildResponse
        const envLimit = RESPONSE_SIZE_LIMITS["containerConfig.data.env"].limit;
        const oversizedEnv = Array.from(
          { length: envLimit + 25 },
          (_, i) => `TEST_VAR${i}=value${i}`,
        );

        const mockAnalysis = createMockAnalysis({
          containerConfig: {
            User: "testuser",
            Env: oversizedEnv, // Will be truncated
          },
          platform: "linux/amd64",
          imageId: "sha256:test-image-id",
          applicationDependenciesScanResults: [
            {
              facts: [
                {
                  type: "depGraph" as const,
                  data: {} as any,
                },
                {
                  type: "testedFiles" as const,
                  data: "/app/test.json",
                },
              ],
              identity: {
                type: "npm",
                args: { platform: "linux/amd64" },
              },
              target: { image: "test-app:v1.0" },
              name: "custom-project-name",
              targetReference: "feature-branch",
            },
          ],
        });

        const result = await buildResponse(
          mockAnalysis as any,
          undefined,
          false,
          ["test-image:latest", "test-image:v1.0"],
          undefined,
          { "target-reference": "main-branch" },
        );

        expect(result.scanResults).toHaveLength(2);

        // Verify main scan result structure is preserved
        const mainScanResult = result.scanResults[0];
        expect(mainScanResult).toHaveProperty("facts");
        expect(mainScanResult).toHaveProperty("target");
        expect(mainScanResult).toHaveProperty("identity");
        expect(mainScanResult).toHaveProperty("targetReference");
        expect(mainScanResult).not.toHaveProperty("name"); // Main scan result doesn't get a name only app projects

        expect(mainScanResult.target).toEqual({
          image: "test", // From depTree.rootPkg.name
        });
        expect(mainScanResult.identity).toEqual({
          type: "test", // From packageFormat
          args: { platform: "linux/amd64" }, // Platform from mock analysis
        });
        expect(mainScanResult.targetReference).toBe("main-branch");

        // Verify facts were processed (truncated)
        const mainContainerConfig = mainScanResult.facts?.find(
          (fact) => fact.type === "containerConfig",
        );
        const mainPluginWarnings = mainScanResult.facts?.find(
          (fact) => fact.type === "pluginWarnings",
        );
        expect(mainContainerConfig?.data.env).toHaveLength(envLimit); // Truncated
        expect(mainPluginWarnings).toBeDefined(); // Created due to truncation

        // Verify application scan result structure is preserved
        const appScanResult = result.scanResults[1];
        expect(appScanResult).toHaveProperty("facts");
        expect(appScanResult).toHaveProperty("target");
        expect(appScanResult).toHaveProperty("identity");
        expect(appScanResult).toHaveProperty("name");
        expect(appScanResult).toHaveProperty("targetReference");

        // Some properties get overridden by buildResponse, others are preserved
        expect(appScanResult.target).toEqual({
          image: "test", // Overridden by buildResponse to depGraph.rootPkg.name
        });
        expect(appScanResult.identity).toEqual({
          type: "npm", // Preserved from original
          args: { platform: "linux/amd64" }, // Preserved from original
        });
        expect(appScanResult.name).toBe("custom-project-name"); // Preserved
        expect(appScanResult.targetReference).toBe("main-branch"); // Overridden by options["target-reference"]

        // Verify facts were processed but other facts preserved
        const appTestedFiles = appScanResult.facts?.find(
          (fact) => fact.type === "testedFiles",
        );
        const appImageId = appScanResult.facts?.find(
          (fact) => fact.type === "imageId",
        );
        const appImageNames = appScanResult.facts?.find(
          (fact) => fact.type === "imageNames",
        );
        const appPluginVersion = appScanResult.facts?.find(
          (fact) => fact.type === "pluginVersion",
        );

        expect(appTestedFiles?.data).toBe("/app/test.json"); // Preserved
        expect(appImageId).toBeDefined(); // Added by buildResponse
        expect(appImageNames?.data).toEqual({
          names: ["test-image:latest", "test-image:v1.0"],
        }); // Added by buildResponse
        expect(appPluginVersion).toBeDefined(); // Added by buildResponse

        // Verify no unexpected properties were added or removed
        const expectedMainKeys = [
          "facts",
          "target",
          "identity",
          "targetReference",
        ];
        const expectedAppKeys = [
          "facts",
          "target",
          "identity",
          "name",
          "targetReference",
        ];

        expect(Object.keys(mainScanResult).sort()).toEqual(
          expectedMainKeys.sort(),
        );
        expect(Object.keys(appScanResult).sort()).toEqual(
          expectedAppKeys.sort(),
        );
      });
    });
  });

  describe("supports exclude-base-image-vulns flag", () => {
    const depTreeWithOsAndFilePkgs = {
      name: "test",
      version: "1.0.0",
      packageFormatVersion: "1.0.0",
      targetOS: {
        name: "alpine",
        version: "3.12",
        prettyName: "Alpine 3.12",
      },
      dependencies: {
        ospkg: {
          name: "ospkg/1.0.0",
          version: "1.0.0",
          dependencies: {
            ostransitive: {
              name: "ostransitive/1.2.3",
              version: "1.2.3",
              dependencies: {},
            },
          },
        },
        dockerfilepkg: {
          name: "dockerfilepkg/2.0.0",
          version: "2.0.0",
          dependencies: {
            dockerfiletransitive: {
              name: "dockerfiletransitive/7.5.1",
              version: "7.5.1",
              dependencies: {},
            },
          },
        },
      },
    };

    const instruction = "RUN apk add dockerfilepkg";
    const encodedInstruction = Buffer.from(instruction).toString("base64");

    const dockerfileAnalysis = {
      baseImage: "alpine:3.12",
      dockerfilePackages: {
        dockerfilepkg: {
          instruction: "RUN apk add dockerfilepkg",
          installCommand: "apk add dockerfilepkg",
        },
      },
      dockerfileLayers: {
        [encodedInstruction]: {
          instruction: instruction,
        },
      },
    };

    const defaultAnalysis = createMockAnalysis({
      depTree: depTreeWithOsAndFilePkgs,
      packageFormat: "apk",
    });

    function getDepPkgs(scanResult: {
      facts?: Array<{ type: string; data: any }>;
    }): string[] {
      const depGraph = scanResult.facts?.find(
        (f) => f.type === "depGraph",
      )?.data;
      if (!depGraph || typeof depGraph.getDepPkgs !== "function") {
        return [];
      }
      return depGraph.getDepPkgs();
    }

    it("should include base image and dockerfile dependencies when excludeBaseImageVulns is false", async () => {
      const result = await buildResponse(
        defaultAnalysis as any,
        dockerfileAnalysis as any,
        false,
        undefined,
        undefined,
        undefined,
      );

      const pkgs = getDepPkgs(result.scanResults[0]);
      const pkgNames = pkgs.map((p: { name: string }) => p.name);
      expect(pkgNames).toContain("ospkg");
      expect(pkgNames).toContain("ostransitive");
      expect(pkgNames).toContain("dockerfilepkg");
      expect(pkgNames).toContain("dockerfiletransitive");
      expect(pkgNames).toHaveLength(4);
    });

    it("should include dockerfile dependencies when excludeBaseImageVulns is true", async () => {
      const result = await buildResponse(
        defaultAnalysis as any,
        dockerfileAnalysis as any,
        true,
        undefined,
        undefined,
        undefined,
      );

      const pkgs = getDepPkgs(result.scanResults[0]);
      const pkgNames = pkgs.map((p: { name: string }) => p.name);
      expect(pkgNames).toContain("dockerfilepkg");
      expect(pkgNames).toContain("dockerfiletransitive");
      expect(pkgNames).toHaveLength(2);
    });

    it("should annotate direct dockerfile dependencies with layer IDs", async () => {
      const result = await buildResponse(
        defaultAnalysis as any,
        dockerfileAnalysis as any,
        false,
        undefined,
        undefined,
        undefined,
      );

      const depGraph = result.scanResults[0].facts?.find(
        (f: { type: string }) => f.type === "depGraph",
      )?.data;
      const pkgs = getDepPkgs(result.scanResults[0]);
      const directDockerfilePkg = pkgs.find((p) => p.name === "dockerfilepkg");
      const nodeInfo = depGraph?.getPkgNodes(directDockerfilePkg);
      const nodeHasMatchingLayerId = nodeInfo.some(
        (n) => n.info?.labels?.dockerLayerId === encodedInstruction,
      );
      expect(nodeHasMatchingLayerId).toBeTruthy();
    });
  });
});
