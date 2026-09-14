import { analyzeStatically } from "../../lib/static";
import { ImageType } from "../../lib/types";

jest.mock("../../lib/analyzer", () => ({
  analyzeStatically: jest.fn().mockResolvedValue({
    imageId: "sha256:abc",
    osRelease: { name: "debian", version: "12", prettyName: "Debian 12" },
    results: [],
    binaries: [],
    imageLayers: [],
    rootFsLayers: [],
    autoDetectedUserInstructions: undefined,
    applicationDependenciesScanResults: [],
    manifestLayers: [],
    platform: "linux/amd64",
  }),
}));

jest.mock("../../lib/parser", () => ({
  parseAnalysisResults: jest.fn().mockReturnValue({
    imageId: "sha256:abc",
    imageLayers: [],
    packageFormat: "deb",
    depInfosList: [],
    targetOS: { name: "debian", version: "12", prettyName: "Debian 12" },
  }),
}));

jest.mock("../../lib/dependency-tree", () => ({
  buildTree: jest.fn().mockReturnValue({ name: "docker-image", version: "1" }),
}));

jest.mock("../../lib/response-builder", () => ({
  buildResponse: jest.fn().mockResolvedValue({ scanResults: [] }),
}));

jest.mock("../../lib/extractor/fetch-registry-provenance-attestations", () => ({
  fetchAttestationsFromRegistry: jest.fn().mockResolvedValue([]),
  parsePlatform: jest.fn().mockReturnValue(undefined),
}));

const {
  fetchAttestationsFromRegistry,
} = require("../../lib/extractor/fetch-registry-provenance-attestations");

describe("analyzeStatically - registry provenance fetching", () => {
  const globs = { include: [], exclude: [] };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("fetches attestations for an image identifier", async () => {
    await analyzeStatically(
      "alpine:3.19",
      undefined,
      ImageType.Identifier,
      "alpine:3.19",
      globs,
      {},
    );

    expect(fetchAttestationsFromRegistry).toHaveBeenCalledTimes(1);
  });

  it("does not fetch attestations for an archive by default", async () => {
    await analyzeStatically(
      "some/image:tag",
      undefined,
      ImageType.DockerArchive,
      "/tmp/image.tar",
      globs,
      { imageNameAndTag: "some/image:tag" },
    );

    expect(fetchAttestationsFromRegistry).not.toHaveBeenCalled();
  });

  it("fetches attestations for an archive when the caller opts in", async () => {
    await analyzeStatically(
      "registry.example.com/some/image:tag",
      undefined,
      ImageType.DockerArchive,
      "/tmp/image.tar",
      globs,
      {
        imageNameAndTag: "registry.example.com/some/image:tag",
        fetchProvenanceFromRegistry: true,
        username: "user",
        password: "pass",
      },
    );

    expect(fetchAttestationsFromRegistry).toHaveBeenCalledTimes(1);
    expect(fetchAttestationsFromRegistry).toHaveBeenCalledWith(
      expect.objectContaining({
        registryBase: "registry.example.com",
        repo: "some/image",
        imageReference: "tag",
        username: "user",
        password: "pass",
      }),
    );
  });

  it("never fails the scan when the attestation fetch throws", async () => {
    fetchAttestationsFromRegistry.mockRejectedValueOnce(
      new Error("connection refused"),
    );

    await expect(
      analyzeStatically(
        "registry.example.com/some/image:tag",
        undefined,
        ImageType.DockerArchive,
        "/tmp/image.tar",
        globs,
        {
          imageNameAndTag: "registry.example.com/some/image:tag",
          fetchProvenanceFromRegistry: true,
        },
      ),
    ).resolves.toBeDefined();
  });
});
