import * as analyzer from "../../lib/analyzer";
import * as depTree from "../../lib/dependency-tree";
import { DockerFileAnalysis } from "../../lib/dockerfile/types";
import * as parser from "../../lib/parser";
import * as responseBuilder from "../../lib/response-builder";
import { analyzeStatically } from "../../lib/static";

jest.mock("../../lib/analyzer");
jest.mock("../../lib/parser");
jest.mock("../../lib/dependency-tree");
jest.mock("../../lib/response-builder");

describe("analyzeStatically", () => {
  beforeEach(() => {
    jest.clearAllMocks();

    (parser.parseAnalysisResults as jest.Mock).mockReturnValue({
      imageId: "test-id",
      imageLayers: [],
      packageFormat: "test-format",
      depInfosList: [],
      targetOS: { name: "test", version: "1" },
    });

    (depTree.buildTree as jest.Mock).mockReturnValue({
      dependencies: {},
    });

    (responseBuilder.buildResponse as jest.Mock).mockReturnValue({
      scanResults: [],
    });
  });

  it("updates baseImage from org.opencontainers.image.base.name label when baseImage is missing", async () => {
    const mockDockerFileAnalysis: DockerFileAnalysis = {
      dockerfilePackages: {},
      dockerfileLayers: {},
      baseImage: undefined,
    };

    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: {
        "org.opencontainers.image.base.name": "alpine:latest",
      },
    });

    await analyzeStatically(
      "test-image",
      mockDockerFileAnalysis,
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      {},
    );

    expect(mockDockerFileAnalysis.baseImage).toEqual("alpine:latest");
  });

  it("updates baseImage from org.opencontainers.image.base.digest label when name is missing", async () => {
    const mockDockerFileAnalysis: DockerFileAnalysis = {
      dockerfilePackages: {},
      dockerfileLayers: {},
      baseImage: undefined,
    };

    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: {
        "org.opencontainers.image.base.digest": "sha256:1234567890abcdef",
      },
    });

    await analyzeStatically(
      "test-image",
      mockDockerFileAnalysis,
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      {},
    );

    expect(mockDockerFileAnalysis.baseImage).toEqual("sha256:1234567890abcdef");
  });

  it("does not update baseImage if it is already present in dockerfileAnalysis", async () => {
    const mockDockerFileAnalysis: DockerFileAnalysis = {
      dockerfilePackages: {},
      dockerfileLayers: {},
      baseImage: "ubuntu:latest",
    };

    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: {
        "org.opencontainers.image.base.name": "alpine:latest",
      },
    });

    await analyzeStatically(
      "test-image",
      mockDockerFileAnalysis,
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      {},
    );

    expect(mockDockerFileAnalysis.baseImage).toEqual("ubuntu:latest");
  });

  it("handles cases where imageLabels are undefined", async () => {
    const mockDockerFileAnalysis: DockerFileAnalysis = {
      dockerfilePackages: {},
      dockerfileLayers: {},
      baseImage: undefined,
    };

    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: undefined,
    });

    await analyzeStatically(
      "test-image",
      mockDockerFileAnalysis,
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      {},
    );

    expect(mockDockerFileAnalysis.baseImage).toBeUndefined();
  });

  it("handles cases where dockerfileAnalysis is undefined", async () => {
    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: {
        "org.opencontainers.image.base.name": "alpine:latest",
      },
    });

    await analyzeStatically(
      "test-image",
      undefined,
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      {},
    );

    const buildResponseCall = (
      responseBuilder.buildResponse as jest.Mock
    ).mock.calls[0];
    // Second argument is dockerfileAnalysis
    expect(buildResponseCall[1]).toMatchObject({ baseImage: "alpine:latest" });
  });

  it("creates synthetic dockerfileAnalysis when dockerfileAnalysis is undefined and OCI labels present", async () => {
    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: {
        "org.opencontainers.image.base.name": "alpine:latest",
      },
    });

    await analyzeStatically(
      "test-image",
      undefined,
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      {},
    );

    const buildResponseCall = (
      responseBuilder.buildResponse as jest.Mock
    ).mock.calls[0];
    expect(buildResponseCall[1]).toEqual({
      baseImage: "alpine:latest",
      dockerfilePackages: {},
      dockerfileLayers: {},
    });
  });

  it("passes excludeBaseImageVulns as false when dockerfileAnalysis is synthetic", async () => {
    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: {
        "org.opencontainers.image.base.name": "alpine:latest",
      },
    });

    await analyzeStatically(
      "test-image",
      undefined,
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      { "exclude-base-image-vulns": "true" },
    );

    const buildResponseCall = (
      responseBuilder.buildResponse as jest.Mock
    ).mock.calls[0];
    // Third argument is excludeBaseImageVulns
    expect(buildResponseCall[2]).toBe(false);
  });

  it("passes excludeBaseImageVulns as true when dockerfileAnalysis is real", async () => {
    (analyzer.analyzeStatically as jest.Mock).mockResolvedValue({
      osRelease: { name: "test", version: "1" },
      imageLabels: {
        "org.opencontainers.image.base.name": "alpine:latest",
      },
    });

    await analyzeStatically(
      "test-image",
      { dockerfilePackages: {}, dockerfileLayers: {}, baseImage: undefined },
      "docker-archive",
      "test-path",
      { include: [], exclude: [] },
      { "exclude-base-image-vulns": "true" },
    );

    const buildResponseCall = (
      responseBuilder.buildResponse as jest.Mock
    ).mock.calls[0];
    // Third argument is excludeBaseImageVulns
    expect(buildResponseCall[2]).toBe(true);
  });
});
