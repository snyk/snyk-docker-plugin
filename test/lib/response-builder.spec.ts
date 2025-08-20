import { StaticAnalysis } from "../../lib/analyzer/types";
import {
  DockerFileAnalysis,
  DockerFilePackages,
} from "../../lib/dockerfile/types";
import { buildResponse } from "../../lib/response-builder";
import * as types from "../../lib/types";

describe("response-builder", () => {
  // Helper functions for creating test data
  const createMockDepsAnalysis = (
    overrides: Partial<
      StaticAnalysis & { depTree: types.DepTree; packageFormat: string }
    > = {},
  ): StaticAnalysis & { depTree: types.DepTree; packageFormat: string } => ({
    depTree: {
      name: "test-image",
      version: "1.0.0",
      packageFormatVersion: "deb:0.0.1",
      dependencies: {},
      targetOS: {
        name: "ubuntu",
        version: "20.04",
        prettyName: "Ubuntu 20.04",
      },
    },
    packageFormat: "deb",
    binaries: [],
    manifestFiles: [],
    autoDetectedUserInstructions: undefined,
    applicationDependenciesScanResults: [],
    imageId: "default-image-id",
    osRelease: {
      name: "ubuntu",
      version: "20.04",
      prettyName: "Ubuntu 20.04",
    },
    results: [],
    imageLayers: [],
    ...overrides,
  });

  const createMockDockerfileAnalysis = (
    overrides: Partial<DockerFileAnalysis> = {},
  ): DockerFileAnalysis => ({
    dockerfilePackages: {},
    dockerfileLayers: {},
    ...overrides,
  });

  const createPackageDep = (
    name: string,
    dependencies = {},
  ): types.DepTreeDep =>
    ({
      name,
      version: "1.0.0",
      dependencies,
    } as any);

  const createDockerfilePackage = (
    installCommand: string,
    packageName: string,
  ): DockerFilePackages => ({
    [packageName]: {
      instruction: `RUN ${installCommand} install ${packageName.split("/")[1]}`,
      installCommand,
    },
  });

  // Helper to build response with common defaults
  const buildTestResponse = async (
    depsAnalysis: ReturnType<typeof createMockDepsAnalysis>,
    dockerfileAnalysis?: DockerFileAnalysis,
    excludeBaseImageVulns = false,
    names?: string[],
  ) => {
    return buildResponse(
      depsAnalysis,
      dockerfileAnalysis,
      excludeBaseImageVulns,
      names,
      undefined,
      undefined,
    );
  };

  // Helper to get fact from result
  const getFact = (result: any, factType: string) => {
    return result.scanResults[0].facts.find((f: any) => f.type === factType);
  };

  describe("excludeBaseImageDeps behavior", () => {
    interface ExcludeTestCase {
      description: string;
      excludeBaseImageVulns: boolean;
      dockerfilePackages?: DockerFilePackages;
      expectedBehavior: string;
    }

    const testCases: ExcludeTestCase[] = [
      {
        description:
          "includes all dependencies when excludeBaseImageVulns is false",
        excludeBaseImageVulns: false,
        dockerfilePackages: createDockerfilePackage("apt-get", "apt/pkgA"),
        expectedBehavior: "include all dependencies",
      },
      {
        description:
          "filters dependencies when excludeBaseImageVulns is true and dockerfile packages exist",
        excludeBaseImageVulns: true,
        dockerfilePackages: createDockerfilePackage("apt-get", "apt/pkgB"),
        expectedBehavior: "only include dockerfile packages",
      },
      {
        description:
          "includes all dependencies when excludeBaseImageVulns is true but no dockerfile packages",
        excludeBaseImageVulns: true,
        dockerfilePackages: undefined,
        expectedBehavior:
          "include all dependencies when no dockerfile packages",
      },
    ];

    test.each(testCases)(
      "$description",
      async ({ excludeBaseImageVulns, dockerfilePackages }) => {
        // Create test dependencies
        const deps = {
          "apt/pkgA": createPackageDep("apt/pkgA"),
          "apt/pkgB": createPackageDep("apt/pkgB"),
          "apt/pkgC": createPackageDep("apt/pkgC"),
        };

        const depsAnalysis = createMockDepsAnalysis({
          depTree: {
            name: "test-image",
            version: "1.0.0",
            packageFormatVersion: "deb:0.0.1",
            dependencies: deps,
            targetOS: {
              name: "ubuntu",
              version: "20.04",
              prettyName: "Ubuntu 20.04",
            },
          },
        });

        const dockerfileAnalysis = dockerfilePackages
          ? createMockDockerfileAnalysis({ dockerfilePackages })
          : undefined;

        const result = await buildTestResponse(
          depsAnalysis,
          dockerfileAnalysis,
          excludeBaseImageVulns,
        );

        const depGraphFact = getFact(result, "depGraph") as any;
        expect(depGraphFact).toBeDefined();
        expect(depGraphFact.data.rootPkg.name).toBe("test-image");
      },
    );
  });

  describe("dockerfile package collection", () => {
    test("collects dockerfile packages and their transitive dependencies", async () => {
      // Create package with transitive dependency
      const deps = {
        "apt/pkgA": createPackageDep("apt/pkgA", {
          "apt/pkgB": createPackageDep("apt/pkgB"),
        }),
      };

      const depsAnalysis = createMockDepsAnalysis({
        depTree: {
          name: "test-image",
          version: "1.0.0",
          packageFormatVersion: "deb:0.0.1",
          dependencies: deps,
          targetOS: {
            name: "ubuntu",
            version: "20.04",
            prettyName: "Ubuntu 20.04",
          },
        },
      });

      const dockerfileAnalysis = createMockDockerfileAnalysis({
        dockerfilePackages: createDockerfilePackage("apt-get", "apt/pkgA"),
      });

      const result = await buildTestResponse(depsAnalysis, dockerfileAnalysis);

      const depGraphFact = getFact(result, "depGraph") as any;
      expect(depGraphFact).toBeDefined();
      expect(depGraphFact.data.rootPkg.name).toBe("test-image");
    });
  });

  describe("fact collection", () => {
    interface FactTestCase {
      factType: string;
      analysisOverrides: any;
      expectedData: any;
      buildResponseArgs?: {
        dockerfileAnalysis?: DockerFileAnalysis;
        excludeBaseImageVulns?: boolean;
        names?: string[];
      };
    }

    const factTestCases: FactTestCase[] = [
      {
        factType: "imageId",
        analysisOverrides: { imageId: "sha256:abc123" },
        expectedData: "sha256:abc123",
      },
      {
        factType: "imageLabels",
        analysisOverrides: {
          imageLabels: { "org.opencontainers.image.version": "1.0.0" },
        },
        expectedData: { "org.opencontainers.image.version": "1.0.0" },
      },
      {
        factType: "imageNames",
        analysisOverrides: {},
        expectedData: { names: ["test-image:latest", "test-image:v1"] },
        buildResponseArgs: {
          names: ["test-image:latest", "test-image:v1"],
        },
      },
    ];

    test.each(factTestCases)(
      "includes $factType fact when available",
      async ({
        factType,
        analysisOverrides,
        expectedData,
        buildResponseArgs,
      }) => {
        const depsAnalysis = createMockDepsAnalysis(analysisOverrides);

        const result = await buildTestResponse(
          depsAnalysis,
          buildResponseArgs?.dockerfileAnalysis,
          buildResponseArgs?.excludeBaseImageVulns ?? false,
          buildResponseArgs?.names,
        );

        const fact = getFact(result, factType) as any;
        expect(fact).toBeDefined();
        expect(fact.data).toEqual(expectedData);
      },
    );
  });
});
