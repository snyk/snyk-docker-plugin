import {
  parseProvenanceAttestations,
  ProvenanceMetadata,
} from "../../../lib/extractor/provenance-parser";
import { ResolvedAttestationManifest } from "../../../lib/extractor/types";

function makeRawAttestation(
  inTotoStatement: Record<string, unknown>,
): ResolvedAttestationManifest {
  const layerDigest = "sha256:layerdigest";
  return {
    manifestDigest: "sha256:abc123",
    manifest: {
      schemaVersion: "2",
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      config: { digest: "sha256:config" },
      layers: [
        {
          digest: layerDigest,
          mediaType: "application/vnd.in-toto+json",
          annotations: {
            "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2",
          },
        },
      ],
    },
    inTotoStatements: {
      [layerDigest]: inTotoStatement as any,
    },
  };
}

describe("provenance-parser", () => {
  describe("SLSA 0.2", () => {
    it("extracts all fields from a remote build", async () => {
      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://slsa.dev/provenance/v0.2",
        subject: [
          {
            name: "pkg:docker/myimage@latest",
            digest: { sha256: "deadbeef1234" },
          },
        ],
        predicate: {
          builder: { id: "https://github.com/docker/buildx" },
          buildType:
            "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
          metadata: {
            buildStartedOn: "2025-01-15T10:30:00Z",
          },
          invocation: {
            configSource: {
              uri: "https://github.com/myorg/myrepo",
              digest: { sha1: "abc123def456" },
              entryPoint: "Dockerfile",
            },
          },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual<ProvenanceMetadata>({
        buildTimestamp: "2025-01-15T10:30:00Z",
        buildConfigDigest: "sha1:abc123def456",
        buildConfigDigestSource: "remote",
        attestedManifestDigest: "sha256:deadbeef1234",
        attestationManifestDigest: "sha256:abc123",
        buildConfigSourceUri: "https://github.com/myorg/myrepo",
        builderId: "https://github.com/docker/buildx",
        buildType:
          "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
        dockerfileMetadata: {
          name: "Dockerfile",
          contents: null,
        },
      });
    });

    it("extracts commit from local build VCS metadata", async () => {
      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://slsa.dev/provenance/v0.2",
        subject: [{ name: "test", digest: { sha256: "aaa111" } }],
        predicate: {
          builder: { id: "buildkit" },
          buildType: "local",
          metadata: {
            buildStartedOn: "2025-02-01T08:00:00Z",
            "https://mobyproject.org/buildkit@v1#metadata": {
              vcs: {
                source: "https://github.com/org/repo.git",
                revision: "localcommitsha",
              },
            },
          },
          invocation: {
            configSource: {
              entryPoint: "docker/Dockerfile.prod",
            },
          },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].buildConfigDigest).toBe("localcommitsha");
      expect(result[0].buildConfigDigestSource).toBe("local");
      // Local builds have no configSource.uri; the source repo falls back to vcs.source.
      expect(result[0].buildConfigSourceUri).toBe(
        "https://github.com/org/repo.git",
      );
      expect(result[0].dockerfileMetadata.name).toBe("docker/Dockerfile.prod");
    });

    it("decodes and parses dockerfile contents from a mode=max build", async () => {
      const dockerfileBase64 = Buffer.from(
        "FROM node:18\nRUN npm install",
      ).toString("base64");

      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://slsa.dev/provenance/v0.2",
        subject: [{ name: "test", digest: { sha256: "bbb222" } }],
        predicate: {
          builder: { id: "buildkit" },
          buildType: "moby",
          metadata: {
            buildStartedOn: "2025-03-01T12:00:00Z",
            "https://mobyproject.org/buildkit@v1#metadata": {
              source: {
                infos: [{ filename: "Dockerfile", data: dockerfileBase64 }],
              },
            },
          },
          invocation: {
            configSource: {
              entryPoint: "Dockerfile",
            },
          },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].dockerfileMetadata.name).toBe("Dockerfile");

      // The raw base64 contents are surfaced verbatim.
      expect(result[0].dockerfileMetadata.contents).toBe(dockerfileBase64);
    });

    it("selects dockerfile contents by filename when multiple sources exist", async () => {
      const wanted = Buffer.from("FROM alpine\n").toString("base64");
      const other = Buffer.from("FROM scratch\n").toString("base64");

      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://slsa.dev/provenance/v0.2",
        subject: [{ name: "test", digest: { sha256: "multi1" } }],
        predicate: {
          builder: { id: "buildkit" },
          buildType: "moby",
          metadata: {
            buildStartedOn: "2025-03-01T12:00:00Z",
            "https://mobyproject.org/buildkit@v1#metadata": {
              source: {
                infos: [
                  { filename: "other/Dockerfile", data: other },
                  { filename: "Dockerfile", data: wanted },
                ],
              },
            },
          },
          invocation: { configSource: { entryPoint: "Dockerfile" } },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].dockerfileMetadata.contents).toBe(wanted);
    });

    it("produces null contents when no source matches the dockerfile name", async () => {
      const a = Buffer.from("FROM alpine\n").toString("base64");
      const b = Buffer.from("FROM scratch\n").toString("base64");

      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://slsa.dev/provenance/v0.2",
        subject: [{ name: "test", digest: { sha256: "multi2" } }],
        predicate: {
          builder: { id: "buildkit" },
          buildType: "moby",
          metadata: {
            buildStartedOn: "2025-03-01T12:00:00Z",
            "https://mobyproject.org/buildkit@v1#metadata": {
              source: {
                infos: [
                  { filename: "a/Dockerfile", data: a },
                  { filename: "b/Dockerfile", data: b },
                ],
              },
            },
          },
          invocation: { configSource: { entryPoint: "Dockerfile" } },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].dockerfileMetadata.name).toBe("Dockerfile");
      expect(result[0].dockerfileMetadata.contents).toBeNull();
    });
  });

  describe("SLSA 1.0", () => {
    it("extracts all fields from a remote build", async () => {
      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [
          {
            name: "pkg:docker/myimage@v2",
            digest: { sha256: "cafebabe9999" },
          },
        ],
        predicate: {
          buildDefinition: {
            buildType:
              "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
            externalParameters: {
              configSource: {
                uri: "https://github.com/team/project",
                digest: { sha1: "remote1sha" },
                path: "build/Dockerfile",
              },
            },
          },
          runDetails: {
            builder: { id: "https://github.com/actions/runner" },
            metadata: {
              startedOn: "2025-06-01T14:00:00Z",
            },
          },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual<ProvenanceMetadata>({
        buildTimestamp: "2025-06-01T14:00:00Z",
        buildConfigDigest: "sha1:remote1sha",
        buildConfigDigestSource: "remote",
        attestedManifestDigest: "sha256:cafebabe9999",
        attestationManifestDigest: "sha256:abc123",
        buildConfigSourceUri: "https://github.com/team/project",
        builderId: "https://github.com/actions/runner",
        buildType:
          "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
        dockerfileMetadata: {
          name: "build/Dockerfile",
          contents: null,
        },
      });
    });

    it("extracts commit from local build VCS metadata", async () => {
      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [{ name: "test", digest: { sha256: "ccc333" } }],
        predicate: {
          buildDefinition: {
            buildType: "local",
            externalParameters: {},
          },
          runDetails: {
            builder: { id: "buildkit" },
            metadata: {
              startedOn: "2025-07-01T09:00:00Z",
              buildkit_metadata: {
                vcs: {
                  source: "https://github.com/team/project.git",
                  revision: "localv1commit",
                },
              },
            },
          },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].buildConfigDigest).toBe("localv1commit");
      expect(result[0].buildConfigDigestSource).toBe("local");
      // Local builds have no configSource.uri; the source repo falls back to vcs.source.
      expect(result[0].buildConfigSourceUri).toBe(
        "https://github.com/team/project.git",
      );
    });

    it("decodes and parses dockerfile contents from a mode=max build", async () => {
      const dockerfileBase64 = Buffer.from(
        "FROM python:3.11\nCOPY . .",
      ).toString("base64");

      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [{ name: "test", digest: { sha256: "ddd444" } }],
        predicate: {
          buildDefinition: {
            buildType: "moby",
            externalParameters: {
              configSource: {
                path: "Dockerfile",
              },
            },
          },
          runDetails: {
            builder: { id: "buildkit" },
            metadata: {
              startedOn: "2025-08-01T10:00:00Z",
              buildkit_metadata: {
                source: {
                  infos: [{ filename: "Dockerfile", data: dockerfileBase64 }],
                },
              },
            },
          },
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].dockerfileMetadata.name).toBe("Dockerfile");
      expect(result[0].dockerfileMetadata.contents).toBe(dockerfileBase64);
    });
  });

  describe("attestation digest", () => {
    it("surfaces the attestation manifest digest distinct from the image digest", async () => {
      const attestation: ResolvedAttestationManifest = {
        manifestDigest: "sha256:attestationmanifest",
        attestedManifestDigest: "sha256:imagedigest",
        manifest: {
          schemaVersion: "2",
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          config: { digest: "sha256:config" },
          layers: [
            {
              digest: "sha256:layerdigest",
              mediaType: "application/vnd.in-toto+json",
            },
          ],
        },
        inTotoStatements: {
          "sha256:layerdigest": {
            _type: "https://in-toto.io/Statement/v0.1",
            predicateType: "https://slsa.dev/provenance/v0.2",
            subject: [{ name: "test", digest: { sha256: "differentsubject" } }],
            predicate: {
              builder: { id: "buildkit" },
              buildType: "test",
              metadata: { buildStartedOn: "2025-01-01T00:00:00Z" },
              invocation: { configSource: {} },
            },
          } as any,
        },
      };

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].attestationManifestDigest).toBe(
        "sha256:attestationmanifest",
      );
      expect(result[0].attestedManifestDigest).toBe("sha256:imagedigest");
    });
  });

  describe("limits and edge cases", () => {
    it("limits to 10 attestations per image", async () => {
      const attestations: ResolvedAttestationManifest[] = Array.from(
        { length: 15 },
        (_, i) =>
          makeRawAttestation({
            _type: "https://in-toto.io/Statement/v0.1",
            predicateType: "https://slsa.dev/provenance/v0.2",
            subject: [{ name: "test", digest: { sha256: `hash${i}` } }],
            predicate: {
              builder: { id: "buildkit" },
              buildType: "test",
              metadata: {
                buildStartedOn: `2025-01-${String(i + 1).padStart(
                  2,
                  "0",
                )}T00:00:00Z`,
              },
              invocation: { configSource: {} },
            },
          }),
      );

      const result = await parseProvenanceAttestations(attestations);

      expect(result).toHaveLength(10);
    });

    it("selects the same digest-sorted subset regardless of input order when over the limit", async () => {
      const makeAttestationWithDigest = (
        manifestDigest: string,
      ): ResolvedAttestationManifest => ({
        manifestDigest,
        manifest: {
          schemaVersion: "2",
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          config: { digest: "sha256:config" },
          layers: [
            {
              digest: "sha256:layer",
              mediaType: "application/vnd.in-toto+json",
            },
          ],
        },
        inTotoStatements: {
          "sha256:layer": {
            _type: "https://in-toto.io/Statement/v0.1",
            predicateType: "https://slsa.dev/provenance/v0.2",
            subject: [{ name: "test", digest: { sha256: "img" } }],
            predicate: {
              builder: { id: "buildkit" },
              buildType: "test",
              metadata: { buildStartedOn: "2025-01-01T00:00:00Z" },
              invocation: { configSource: {} },
            },
          } as any,
        },
      });

      const digests = Array.from(
        { length: 15 },
        (_, i) => `sha256:att-${String(i).padStart(2, "0")}`,
      );
      const expectedSubset = [...digests].sort().slice(0, 10);

      const ascending = digests.map(makeAttestationWithDigest);
      const shuffled = [...ascending].reverse();

      const resultAscending = (
        await parseProvenanceAttestations(ascending)
      ).map((r) => r.attestationManifestDigest);
      const resultShuffled = (await parseProvenanceAttestations(shuffled)).map(
        (r) => r.attestationManifestDigest,
      );

      expect(resultAscending).toEqual(expectedSubset);
      expect(resultShuffled).toEqual(expectedSubset);
    });

    it("skips layers without inTotoStatement", async () => {
      const attestation: ResolvedAttestationManifest = {
        manifestDigest: "sha256:abc",
        manifest: {
          schemaVersion: "2",
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          config: { digest: "sha256:config" },
          layers: [
            {
              digest: "sha256:noblob",
              mediaType: "application/vnd.in-toto+json",
            },
          ],
        },
        inTotoStatements: {},
      };

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(0);
    });

    it("skips unsupported predicate types", async () => {
      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://example.com/custom/v1",
        subject: [{ name: "test", digest: { sha256: "eee555" } }],
        predicate: {
          something: "custom",
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(0);
    });

    it("handles missing fields gracefully", async () => {
      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://slsa.dev/provenance/v0.2",
        subject: [{ name: "test", digest: { sha256: "abc123" } }],
        predicate: {
          builder: {},
          buildType: "",
          metadata: {},
          invocation: {},
        },
      });

      const result = await parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual<ProvenanceMetadata>({
        buildTimestamp: null,
        buildConfigDigest: null,
        buildConfigDigestSource: null,
        attestedManifestDigest: "sha256:abc123",
        attestationManifestDigest: "sha256:abc123",
        buildConfigSourceUri: null,
        builderId: "",
        buildType: "",
        dockerfileMetadata: {
          name: "Dockerfile",
          contents: null,
        },
      });
    });
  });
});
