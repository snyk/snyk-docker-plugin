import { getManifest } from "@snyk/docker-registry-v2-client";

import { fetchDistributionDigestsFromRegistry } from "../../../lib/extractor/fetch-registry-distribution-digests";

jest.mock("@snyk/docker-registry-v2-client", () => ({
  ...jest.requireActual("@snyk/docker-registry-v2-client"),
  getManifest: jest.fn(),
}));

const mockGetManifest = getManifest as jest.MockedFunction<typeof getManifest>;

const CONFIG_DIGEST = `sha256:${"c".repeat(64)}`;
const MANIFEST_DIGEST = `sha256:${"a".repeat(64)}`;
const INDEX_DIGEST = `sha256:${"b".repeat(64)}`;

const ref = {
  registryBase: "registry-1.docker.io",
  repo: "library/nginx",
  imageReference: "1.27",
  username: "user",
  password: "pass",
  expectedConfigDigest: CONFIG_DIGEST,
};

function manifestWith(configDigest: string) {
  return {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { digest: configDigest },
    layers: [],
    manifestDigest: MANIFEST_DIGEST,
    indexDigest: INDEX_DIGEST,
  } as any;
}

describe("fetchDistributionDigestsFromRegistry", () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it("returns manifest and index digests when the config digest matches the scanned image", async () => {
    mockGetManifest.mockResolvedValue(manifestWith(CONFIG_DIGEST));

    const result = await fetchDistributionDigestsFromRegistry({
      ...ref,
      platform: { os: "linux", architecture: "amd64" },
    });

    expect(result).toEqual({ manifest: MANIFEST_DIGEST, index: INDEX_DIGEST });
    expect(mockGetManifest).toHaveBeenCalledWith(
      "registry-1.docker.io",
      "library/nginx",
      "1.27",
      "user",
      "pass",
      expect.objectContaining({
        acceptManifest: expect.stringContaining(
          "application/vnd.oci.image.index.v1+json",
        ),
        response_timeout: expect.any(Number),
        read_timeout: expect.any(Number),
      }),
      { os: "linux", architecture: "amd64" },
    );
  });

  it("returns undefined when the registry tag points to a different image than the one scanned", async () => {
    mockGetManifest.mockResolvedValue(manifestWith(`sha256:${"d".repeat(64)}`));

    expect(await fetchDistributionDigestsFromRegistry(ref)).toBeUndefined();
  });

  it("returns undefined when the registry request fails", async () => {
    mockGetManifest.mockRejectedValue(new Error("unauthorized"));

    expect(await fetchDistributionDigestsFromRegistry(ref)).toBeUndefined();
  });

  it("retries arm64 with the default v8 variant used by registries", async () => {
    mockGetManifest
      .mockRejectedValueOnce(
        new Error('no supported manifest found for platform: {"os":"linux"}'),
      )
      .mockResolvedValueOnce(manifestWith(CONFIG_DIGEST));

    const result = await fetchDistributionDigestsFromRegistry({
      ...ref,
      platform: { os: "linux", architecture: "arm64" },
    });

    expect(result).toEqual({ manifest: MANIFEST_DIGEST, index: INDEX_DIGEST });
    expect(mockGetManifest).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.anything(),
      { os: "linux", architecture: "arm64", variant: "v8" },
    );
  });

  it("returns only the manifest digest for single-platform images", async () => {
    mockGetManifest.mockResolvedValue({
      ...manifestWith(CONFIG_DIGEST),
      indexDigest: undefined,
    });

    expect(await fetchDistributionDigestsFromRegistry(ref)).toEqual({
      manifest: MANIFEST_DIGEST,
      index: undefined,
    });
  });
});
