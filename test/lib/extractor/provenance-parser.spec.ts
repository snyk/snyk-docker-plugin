import {
  parseProvenanceAttestations,
  ProvenanceAttestation,
} from "../../../lib/extractor/provenance-parser";
import { RawProvenanceAttestation } from "../../../lib/extractor/types";

function makeRawAttestation(
  inTotoStatement: Record<string, unknown>,
): RawProvenanceAttestation {
  return {
    attestationManifestDigest: "sha256:abc123",
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    annotations: {
      "vnd.docker.reference.digest": "sha256:targetdigest",
      "vnd.docker.reference.type": "attestation-manifest",
    },
    provenanceLayers: [
      {
        digest: "sha256:layerdigest",
        mediaType: "application/vnd.in-toto+json",
        annotations: {
          "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2",
        },
        inTotoStatement: inTotoStatement as any,
      },
    ],
  };
}

describe("provenance-parser", () => {
  describe("SLSA 0.2", () => {
    it("extracts all fields from a remote build", () => {
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

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual<ProvenanceAttestation>({
        buildTimestamp: "2025-01-15T10:30:00Z",
        commit: "abc123def456",
        manifestDigest: "sha256:deadbeef1234",
        repoUri: "https://github.com/myorg/myrepo",
        builderId: "https://github.com/docker/buildx",
        buildType:
          "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
        dockerfileMetadata: {
          path: "Dockerfile",
          contents: null,
        },
      });
    });

    it("extracts commit from local build VCS metadata", () => {
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

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].commit).toBe("localcommitsha");
      expect(result[0].dockerfileMetadata.path).toBe("docker/Dockerfile.prod");
    });

    it("extracts dockerfile contents from mode=max build", () => {
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
                infos: [{ data: dockerfileBase64 }],
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

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].dockerfileMetadata.contents).toBe(dockerfileBase64);
    });
  });

  describe("SLSA 1.0", () => {
    it("extracts all fields from a remote build", () => {
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

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual<ProvenanceAttestation>({
        buildTimestamp: "2025-06-01T14:00:00Z",
        commit: "remote1sha",
        manifestDigest: "sha256:cafebabe9999",
        repoUri: "https://github.com/team/project",
        builderId: "https://github.com/actions/runner",
        buildType:
          "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
        dockerfileMetadata: {
          path: "build/Dockerfile",
          contents: null,
        },
      });
    });

    it("extracts commit from local build VCS metadata", () => {
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
                  revision: "localv1commit",
                },
              },
            },
          },
        },
      });

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].commit).toBe("localv1commit");
    });

    it("extracts dockerfile contents from mode=max build", () => {
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
                  infos: [{ data: dockerfileBase64 }],
                },
              },
            },
          },
        },
      });

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0].dockerfileMetadata.contents).toBe(dockerfileBase64);
    });
  });

  describe("limits and edge cases", () => {
    it("limits to 10 attestations per image", () => {
      const attestations: RawProvenanceAttestation[] = Array.from(
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

      const result = parseProvenanceAttestations(attestations);

      expect(result).toHaveLength(10);
    });

    it("skips layers without inTotoStatement", () => {
      const attestation: RawProvenanceAttestation = {
        attestationManifestDigest: "sha256:abc",
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        annotations: {},
        provenanceLayers: [
          {
            digest: "sha256:noblob",
            mediaType: "application/vnd.in-toto+json",
          },
        ],
      };

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(0);
    });

    it("skips unsupported predicate types", () => {
      const attestation = makeRawAttestation({
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://example.com/custom/v1",
        subject: [{ name: "test", digest: { sha256: "eee555" } }],
        predicate: {
          something: "custom",
        },
      });

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(0);
    });

    it("handles missing fields gracefully", () => {
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

      const result = parseProvenanceAttestations([attestation]);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual<ProvenanceAttestation>({
        buildTimestamp: null,
        commit: null,
        manifestDigest: "sha256:abc123",
        repoUri: null,
        builderId: "",
        buildType: "",
        dockerfileMetadata: {
          path: "Dockerfile",
          contents: null,
        },
      });
    });
  });
});
