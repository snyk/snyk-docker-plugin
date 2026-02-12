import { buildResponse } from "../../lib/response-builder";

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

      // Should create a containerConfig fact with null data when containerConfig is null
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
  });
});
