import {
  getAttestationManifest,
  getLayer,
} from "@snyk/docker-registry-v2-client";

import {
  fetchAttestationsFromRegistry,
  keepAttestationsForManifest,
  parsePlatform,
} from "../../../lib/extractor/fetch-registry-provenance-attestations";

jest.mock("@snyk/docker-registry-v2-client", () => ({
  getAttestationManifest: jest.fn(),
  getLayer: jest.fn(),
}));

const mockGetAttestationManifest =
  getAttestationManifest as jest.MockedFunction<typeof getAttestationManifest>;
const mockGetLayer = getLayer as jest.MockedFunction<typeof getLayer>;

const IN_TOTO = "application/vnd.in-toto+json";
const SLSA_PROVENANCE = "https://slsa.dev/provenance/v0.2";

const ref = {
  registryBase: "registry-1.docker.io",
  repo: "library/myimage",
  imageReference: "latest",
};

const statement = { predicateType: SLSA_PROVENANCE };
const statementBlob = Buffer.from(JSON.stringify(statement));

describe("fetch-registry-provenance-attestations", () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });
  it("parses os/architecture/variant", () => {
    expect(parsePlatform("linux/arm64/v8")).toEqual({
      os: "linux",
      architecture: "arm64",
      variant: "v8",
    });
  });

  describe("fetchAttestationsFromRegistry", () => {
    it("fetches the attestation manifest and its in-toto layers", async () => {
      mockGetAttestationManifest.mockResolvedValue({
        manifestDigest: "sha256:attmanifest",
        config: { digest: "sha256:config" },
        layers: [{ digest: "sha256:layer1", mediaType: IN_TOTO }],
      } as any);
      mockGetLayer.mockResolvedValue(statementBlob);

      const result = await fetchAttestationsFromRegistry(ref);

      expect(result).toHaveLength(1);
      expect(result[0].manifestDigest).toEqual("sha256:attmanifest");
      expect(result[0].manifest.layers).toEqual([
        { digest: "sha256:layer1", mediaType: IN_TOTO },
      ]);
      expect(result[0].inTotoStatements["sha256:layer1"]).toEqual(statement);
    });

    it("passes credentials and platform through to the registry client", async () => {
      mockGetAttestationManifest.mockResolvedValue({
        manifestDigest: "sha256:attmanifest",
        config: { digest: "sha256:config" },
        layers: [{ digest: "sha256:layer1", mediaType: IN_TOTO }],
      } as any);
      mockGetLayer.mockResolvedValue(statementBlob);

      const platform = { os: "linux", architecture: "amd64" };
      await fetchAttestationsFromRegistry({
        ...ref,
        username: "user",
        password: "pass",
        platform,
      });

      expect(mockGetAttestationManifest).toHaveBeenCalledWith(
        ref.registryBase,
        ref.repo,
        ref.imageReference,
        "user",
        "pass",
        undefined,
        platform,
      );
      expect(mockGetLayer).toHaveBeenCalledWith(
        ref.registryBase,
        ref.repo,
        "sha256:layer1",
        "user",
        "pass",
      );
    });

    it("fetches only the provenance attestation even when an SBOM attestation is also present", async () => {
      mockGetAttestationManifest.mockResolvedValue({
        manifestDigest: "sha256:attmanifest",
        config: { digest: "sha256:config" },
        layers: [
          {
            digest: "sha256:sbom",
            mediaType: IN_TOTO,
            annotations: {
              "in-toto.io/predicate-type": "https://spdx.dev/Document",
            },
          },
          {
            digest: "sha256:prov",
            mediaType: IN_TOTO,
            annotations: { "in-toto.io/predicate-type": SLSA_PROVENANCE },
          },
        ],
      } as any);
      mockGetLayer.mockResolvedValue(statementBlob);

      const result = await fetchAttestationsFromRegistry(ref);

      // The SBOM blob is never downloaded — only the provenance layer.
      expect(mockGetLayer).toHaveBeenCalledTimes(1);
      expect(mockGetLayer).toHaveBeenCalledWith(
        ref.registryBase,
        ref.repo,
        "sha256:prov",
        undefined,
        undefined,
      );
      expect(Object.keys(result[0].inTotoStatements)).toEqual(["sha256:prov"]);
    });

    it("returns [] when there is no provenance attestation", async () => {
      mockGetAttestationManifest.mockResolvedValue({
        manifestDigest: "sha256:attmanifest",
        config: { digest: "sha256:config" },
        layers: [
          {
            digest: "sha256:sbom",
            mediaType: IN_TOTO,
            annotations: {
              "in-toto.io/predicate-type": "https://spdx.dev/Document",
            },
          },
        ],
      } as any);

      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
      expect(mockGetLayer).not.toHaveBeenCalled();
    });

    it("skips an attestation layer larger than the 2 MB limit without downloading it", async () => {
      mockGetAttestationManifest.mockResolvedValue({
        manifestDigest: "sha256:attmanifest",
        config: { digest: "sha256:config" },
        layers: [
          {
            digest: "sha256:huge",
            mediaType: IN_TOTO,
            annotations: { "in-toto.io/predicate-type": SLSA_PROVENANCE },
            size: 2 * 1024 * 1024 + 1,
          },
        ],
      } as any);

      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
      expect(mockGetLayer).not.toHaveBeenCalled();
    });
  });

  describe("keepAttestationsForManifest", () => {
    const AMD64_MANIFEST = `sha256:${"a".repeat(64)}`;
    const ARM64_MANIFEST = `sha256:${"b".repeat(64)}`;
    const statementFor = (manifestDigest: string) => ({
      predicateType: SLSA_PROVENANCE,
      subject: [{ digest: { sha256: manifestDigest.replace("sha256:", "") } }],
    });
    const attestationFor = (manifestDigest: string) => ({
      manifestDigest: "sha256:attmanifest",
      manifest: {
        schemaVersion: "2",
        config: { digest: "sha256:config" },
        layers: [{ digest: "sha256:layer1", mediaType: IN_TOTO }],
      } as any,
      inTotoStatements: { "sha256:layer1": statementFor(manifestDigest) },
    });

    it("keeps attestations whose subject is the scanned manifest", () => {
      const result = keepAttestationsForManifest(
        [attestationFor(ARM64_MANIFEST)],
        ARM64_MANIFEST,
      );

      expect(result).toHaveLength(1);
      expect(result[0].attestedManifestDigest).toEqual(ARM64_MANIFEST);
      expect(Object.keys(result[0].inTotoStatements)).toEqual([
        "sha256:layer1",
      ]);
    });

    it("drops attestations for another platform's manifest", () => {
      expect(
        keepAttestationsForManifest(
          [attestationFor(AMD64_MANIFEST)],
          ARM64_MANIFEST,
        ),
      ).toEqual([]);
    });

    it("drops attestations when the scanned manifest digest is unknown", () => {
      expect(
        keepAttestationsForManifest(
          [attestationFor(ARM64_MANIFEST)],
          undefined,
        ),
      ).toEqual([]);
    });

    it("skips malformed statements and keeps valid ones", () => {
      const attestation = attestationFor(ARM64_MANIFEST);
      attestation.inTotoStatements = {
        "sha256:null": null,
        "sha256:badsubject": { predicateType: SLSA_PROVENANCE, subject: "x" },
        "sha256:baddigest": { subject: [null, { digest: "x" }] },
        ...attestation.inTotoStatements,
      } as any;

      const result = keepAttestationsForManifest([attestation], ARM64_MANIFEST);

      expect(result).toHaveLength(1);
      expect(Object.keys(result[0].inTotoStatements)).toEqual([
        "sha256:layer1",
      ]);
    });
  });
});
