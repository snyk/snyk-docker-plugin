import { createHash } from "crypto";
import {
  getAttestationManifest,
  getLayer,
} from "@snyk/docker-registry-v2-client";

import {
  fetchAttestationsFromRegistry,
  parsePlatform,
} from "../../../lib/extractor/registry-attestations";

jest.mock("@snyk/docker-registry-v2-client", () => ({
  getAttestationManifest: jest.fn(),
  getLayer: jest.fn(),
}));

const mockGetAttestationManifest =
  getAttestationManifest as jest.MockedFunction<typeof getAttestationManifest>;
const mockGetLayer = getLayer as jest.MockedFunction<typeof getLayer>;

const IN_TOTO_MEDIATYPE = "application/vnd.in-toto+json";

const ref = {
  registryBase: "registry-1.docker.io",
  repo: "library/myimage",
  imageReference: "latest",
};

const inTotoStatement = {
  _type: "https://in-toto.io/Statement/v0.1",
  predicateType: "https://slsa.dev/provenance/v0.2",
  subject: [{ name: "myimage", digest: { sha256: "deadbeef" } }],
  predicate: { buildType: "https://mobyproject.org/buildkit@v1" },
};

function attestationManifest(layers: any[]) {
  return {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { digest: "sha256:config" },
    layers,
  };
}

describe("registry-attestations", () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe("parsePlatform", () => {
    it("returns undefined when no platform is given", () => {
      expect(parsePlatform(undefined)).toBeUndefined();
      expect(parsePlatform("")).toBeUndefined();
    });

    it("parses os/architecture", () => {
      expect(parsePlatform("linux/amd64")).toEqual({
        os: "linux",
        architecture: "amd64",
        variant: undefined,
      });
    });

    it("parses os/architecture/variant", () => {
      expect(parsePlatform("linux/arm64/v8")).toEqual({
        os: "linux",
        architecture: "arm64",
        variant: "v8",
      });
    });

    it("returns undefined when architecture is missing", () => {
      expect(parsePlatform("linux")).toBeUndefined();
    });
  });

  describe("fetchAttestationsFromRegistry", () => {
    it("fetches the attestation manifest and its in-toto layers", async () => {
      const layerDigest = "sha256:layer1";
      const manifest = attestationManifest([
        { digest: layerDigest, mediaType: IN_TOTO_MEDIATYPE },
      ]);
      mockGetAttestationManifest.mockResolvedValue(manifest as any);
      mockGetLayer.mockResolvedValue(
        Buffer.from(JSON.stringify(inTotoStatement)),
      );

      const result = await fetchAttestationsFromRegistry(ref);

      expect(result).toHaveLength(1);
      expect(result[0].manifest).toBe(manifest);
      expect(result[0].inTotoStatements[layerDigest]).toEqual(inTotoStatement);
      // manifestDigest is a content-derived sha256 of the manifest JSON.
      const expectedDigest =
        "sha256:" +
        createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
      expect(result[0].manifestDigest).toEqual(expectedDigest);
    });

    it("passes credentials and platform through to the registry client", async () => {
      const layerDigest = "sha256:layer1";
      const manifest = attestationManifest([
        { digest: layerDigest, mediaType: IN_TOTO_MEDIATYPE },
      ]);
      mockGetAttestationManifest.mockResolvedValue(manifest as any);
      mockGetLayer.mockResolvedValue(
        Buffer.from(JSON.stringify(inTotoStatement)),
      );

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
        layerDigest,
        "user",
        "pass",
      );
    });

    it("skips layers that are not in-toto statements", async () => {
      const intotoDigest = "sha256:intoto";
      const manifest = attestationManifest([
        {
          digest: "sha256:other",
          mediaType: "application/vnd.oci.image.layer",
        },
        { digest: intotoDigest, mediaType: IN_TOTO_MEDIATYPE },
      ]);
      mockGetAttestationManifest.mockResolvedValue(manifest as any);
      mockGetLayer.mockResolvedValue(
        Buffer.from(JSON.stringify(inTotoStatement)),
      );

      const result = await fetchAttestationsFromRegistry(ref);

      expect(mockGetLayer).toHaveBeenCalledTimes(1);
      expect(mockGetLayer).toHaveBeenCalledWith(
        ref.registryBase,
        ref.repo,
        intotoDigest,
        undefined,
        undefined,
      );
      expect(Object.keys(result[0].inTotoStatements)).toEqual([intotoDigest]);
    });

    it("fetches only the provenance layer when an SBOM attestation is also present", async () => {
      const provDigest = "sha256:prov";
      const sbomDigest = "sha256:sbom";
      const manifest = attestationManifest([
        {
          digest: sbomDigest,
          mediaType: IN_TOTO_MEDIATYPE,
          annotations: {
            "in-toto.io/predicate-type": "https://spdx.dev/Document",
          },
        },
        {
          digest: provDigest,
          mediaType: IN_TOTO_MEDIATYPE,
          annotations: {
            "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2",
          },
        },
      ]);
      mockGetAttestationManifest.mockResolvedValue(manifest as any);
      mockGetLayer.mockResolvedValue(
        Buffer.from(JSON.stringify(inTotoStatement)),
      );

      const result = await fetchAttestationsFromRegistry(ref);

      // The SBOM blob is never downloaded — only the provenance layer.
      expect(mockGetLayer).toHaveBeenCalledTimes(1);
      expect(mockGetLayer).toHaveBeenCalledWith(
        ref.registryBase,
        ref.repo,
        provDigest,
        undefined,
        undefined,
      );
      expect(Object.keys(result[0].inTotoStatements)).toEqual([provDigest]);
    });

    it("returns [] when the only in-toto layer is a non-provenance predicate", async () => {
      mockGetAttestationManifest.mockResolvedValue(
        attestationManifest([
          {
            digest: "sha256:sbom",
            mediaType: IN_TOTO_MEDIATYPE,
            annotations: {
              "in-toto.io/predicate-type": "https://spdx.dev/Document",
            },
          },
        ]) as any,
      );

      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
      expect(mockGetLayer).not.toHaveBeenCalled();
    });

    it("falls back to fetching an in-toto layer that has no predicate-type annotation", async () => {
      const digest = "sha256:noannotation";
      mockGetAttestationManifest.mockResolvedValue(
        attestationManifest([{ digest, mediaType: IN_TOTO_MEDIATYPE }]) as any,
      );
      mockGetLayer.mockResolvedValue(
        Buffer.from(JSON.stringify(inTotoStatement)),
      );

      const result = await fetchAttestationsFromRegistry(ref);

      expect(mockGetLayer).toHaveBeenCalledTimes(1);
      expect(Object.keys(result[0].inTotoStatements)).toEqual([digest]);
    });

    it("returns [] when getAttestationManifest throws", async () => {
      mockGetAttestationManifest.mockRejectedValue(new Error("404 not found"));

      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
      expect(mockGetLayer).not.toHaveBeenCalled();
    });

    it("returns [] when no attestation manifest is present", async () => {
      mockGetAttestationManifest.mockResolvedValue(undefined as any);
      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
    });

    it("returns [] when the manifest has no layers", async () => {
      mockGetAttestationManifest.mockResolvedValue(
        attestationManifest([]) as any,
      );
      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
    });

    it("returns [] when the manifest has no in-toto layers", async () => {
      mockGetAttestationManifest.mockResolvedValue(
        attestationManifest([
          {
            digest: "sha256:other",
            mediaType: "application/vnd.oci.image.layer",
          },
        ]) as any,
      );
      const result = await fetchAttestationsFromRegistry(ref);
      expect(result).toEqual([]);
      expect(mockGetLayer).not.toHaveBeenCalled();
    });

    it("skips a layer whose blob cannot be fetched, and returns [] if none remain", async () => {
      const manifest = attestationManifest([
        { digest: "sha256:layer1", mediaType: IN_TOTO_MEDIATYPE },
      ]);
      mockGetAttestationManifest.mockResolvedValue(manifest as any);
      mockGetLayer.mockRejectedValue(new Error("blob 500"));

      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
    });

    it("skips a layer whose blob is not valid JSON, and returns [] if none remain", async () => {
      const manifest = attestationManifest([
        { digest: "sha256:layer1", mediaType: IN_TOTO_MEDIATYPE },
      ]);
      mockGetAttestationManifest.mockResolvedValue(manifest as any);
      mockGetLayer.mockResolvedValue(Buffer.from("not-json"));

      expect(await fetchAttestationsFromRegistry(ref)).toEqual([]);
    });

    it("keeps usable layers when a sibling layer fails to parse", async () => {
      const goodDigest = "sha256:good";
      const badDigest = "sha256:bad";
      const manifest = attestationManifest([
        { digest: badDigest, mediaType: IN_TOTO_MEDIATYPE },
        { digest: goodDigest, mediaType: IN_TOTO_MEDIATYPE },
      ]);
      mockGetAttestationManifest.mockResolvedValue(manifest as any);
      mockGetLayer.mockImplementation(async (_base, _repo, digest) => {
        if (digest === badDigest) {
          return Buffer.from("not-json");
        }
        return Buffer.from(JSON.stringify(inTotoStatement));
      });

      const result = await fetchAttestationsFromRegistry(ref);

      expect(result).toHaveLength(1);
      expect(Object.keys(result[0].inTotoStatements)).toEqual([goodDigest]);
    });
  });
});
