import { StaticAnalysis } from "../../lib/analyzer/types";
import { fetchDistributionDigestsFromRegistry } from "../../lib/extractor/fetch-registry-distribution-digests";
import { fetchAttestationsFromRegistry } from "../../lib/extractor/fetch-registry-provenance-attestations";
import { resolveRegistryCredentials } from "../../lib/extractor/registry-credentials";
import {
  fetchRegistryMetadata,
  REGISTRY_METADATA_DEADLINE_MS,
} from "../../lib/static";

jest.mock("../../lib/extractor/registry-credentials");
jest.mock("../../lib/extractor/fetch-registry-distribution-digests");
jest.mock("../../lib/extractor/fetch-registry-provenance-attestations", () => ({
  ...jest.requireActual(
    "../../lib/extractor/fetch-registry-provenance-attestations",
  ),
  fetchAttestationsFromRegistry: jest.fn(),
}));

const mockCredentials = resolveRegistryCredentials as jest.MockedFunction<
  typeof resolveRegistryCredentials
>;
const mockDigests = fetchDistributionDigestsFromRegistry as jest.MockedFunction<
  typeof fetchDistributionDigestsFromRegistry
>;
const mockAttestations = fetchAttestationsFromRegistry as jest.MockedFunction<
  typeof fetchAttestationsFromRegistry
>;

const ARM64_MANIFEST = `sha256:${"b".repeat(64)}`;
const INDEX = `sha256:${"c".repeat(64)}`;
const analysis = {
  imageId: `sha256:${"1".repeat(64)}`,
  platform: "linux/arm64",
} as unknown as StaticAnalysis;

const attestation = (statement: unknown) => ({
  manifestDigest: "sha256:attmanifest",
  manifest: { schemaVersion: "2", config: { digest: "x" }, layers: [] } as any,
  inTotoStatements: { "sha256:layer1": statement as any },
});

describe("fetchRegistryMetadata", () => {
  beforeEach(() => {
    jest.resetAllMocks();
    mockCredentials.mockResolvedValue({});
    mockDigests.mockResolvedValue({ manifest: ARM64_MANIFEST, index: INDEX });
  });

  it("uses the scanned platform for both lookups when --platform is omitted", async () => {
    mockAttestations.mockResolvedValue([]);

    await fetchRegistryMetadata("org/image:1.0", analysis, {});

    const arm64 = { os: "linux", architecture: "arm64", variant: undefined };
    expect(mockDigests.mock.calls[0][0].platform).toEqual(arm64);
    expect(mockAttestations.mock.calls[0][0].platform).toEqual(arm64);
  });

  it("prefers the requested platform for both lookups", async () => {
    mockAttestations.mockResolvedValue([]);

    await fetchRegistryMetadata("org/image:1.0", analysis, {
      platform: "linux/amd64",
    });

    const amd64 = { os: "linux", architecture: "amd64", variant: undefined };
    expect(mockDigests.mock.calls[0][0].platform).toEqual(amd64);
    expect(mockAttestations.mock.calls[0][0].platform).toEqual(amd64);
  });

  it("keeps the digests when the attestation lookup fails", async () => {
    mockAttestations.mockRejectedValue(new Error("boom"));

    const result = await fetchRegistryMetadata("org/image:1.0", analysis, {});

    expect(result.digests).toEqual({ manifest: ARM64_MANIFEST, index: INDEX });
  });

  it("keeps the digests when an attestation statement is malformed", async () => {
    mockAttestations.mockResolvedValue([attestation(null)]);

    const result = await fetchRegistryMetadata("org/image:1.0", analysis, {});

    expect(result.digests).toEqual({ manifest: ARM64_MANIFEST, index: INDEX });
    expect(result.attestations).toEqual([]);
  });

  it("gives up on registry metadata that never arrives", async () => {
    jest.useFakeTimers();
    try {
      mockAttestations.mockReturnValue(new Promise(() => undefined));
      mockDigests.mockReturnValue(new Promise(() => undefined));

      const pending = fetchRegistryMetadata("org/image:1.0", analysis, {});
      await jest.advanceTimersByTimeAsync(REGISTRY_METADATA_DEADLINE_MS);

      await expect(pending).resolves.toEqual({});
    } finally {
      jest.useRealTimers();
    }
  });

  it.each([
    "nginx:1.27",
    "docker.io/nginx:1.27",
    "index.docker.io/nginx:1.27",
    "registry-1.docker.io/library/nginx:1.27",
  ])("uses the Docker Hub official repository for %s", async (image) => {
    mockAttestations.mockResolvedValue([]);

    await fetchRegistryMetadata(image, analysis, {});

    const ref = mockDigests.mock.calls[0][0];
    expect(ref.registryBase).toEqual("registry-1.docker.io");
    expect(ref.repo).toEqual("library/nginx");
    expect(mockAttestations.mock.calls[0][0].repo).toEqual("library/nginx");
  });
});
