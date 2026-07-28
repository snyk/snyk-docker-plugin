import * as Debug from "debug";
import { InTotoStatement, ResolvedAttestationManifest } from "./types";

const debug = Debug("snyk");

const MAX_ATTESTATIONS_PER_IMAGE = 10;

type SlsaProvenanceVersion =
  | "https://slsa.dev/provenance/v0.2"
  | "https://slsa.dev/provenance/v1";

export interface DockerfileMetadata {
  name: string;
  contents: string | null;
}

export interface ProvenanceMetadata {
  buildTimestamp: string | null;
  buildConfigDigest: string | null;
  buildConfigDigestSource: "remote" | "local" | null;
  attestedManifestDigest: string;
  attestationManifestDigest: string;
  buildConfigSourceUri: string | null;
  builderId: string;
  buildType: string;
  dockerfileMetadata: DockerfileMetadata;
}

interface BuildkitSourceInfo {
  filename?: string;
  data?: string;
}

interface SlsaPredicateV0_2 {
  builder?: { id?: string };
  buildType?: string;
  metadata?: {
    buildStartedOn?: string;
    "https://mobyproject.org/buildkit@v1#metadata"?: {
      vcs?: { source?: string; revision?: string };
      source?: {
        infos?: BuildkitSourceInfo[];
      };
    };
  };
  invocation?: {
    configSource?: {
      uri?: string;
      digest?: { [algorithm: string]: string };
      entryPoint?: string;
    };
  };
}

interface SlsaPredicateV1_0 {
  buildDefinition?: {
    buildType?: string;
    externalParameters?: {
      configSource?: {
        uri?: string;
        digest?: { [algorithm: string]: string };
        path?: string;
      };
    };
  };
  runDetails?: {
    builder?: { id?: string };
    metadata?: {
      startedOn?: string;
      buildkit_metadata?: {
        vcs?: { source?: string; revision?: string };
        source?: {
          infos?: BuildkitSourceInfo[];
        };
      };
    };
  };
}

function getEncodedDockerfileContents(
  infos: BuildkitSourceInfo[] | undefined,
  dockerfileName: string,
): string | null {
  const match = infos?.find((info) => info.filename === dockerfileName);
  return match?.data ?? null;
}

function getConfigSourceCommit(digest?: {
  [algorithm: string]: string;
}): string | null {
  if (!digest) {
    return null;
  }

  const [algorithm, value] = Object.entries(digest)[0] ?? [];
  if (!algorithm || !value) {
    return null;
  }

  return `${algorithm}:${value}`;
}

async function extractFieldsSlsaV0_2(
  predicate: SlsaPredicateV0_2,
  attestedManifestDigest: string,
  attestationManifestDigest: string,
): Promise<ProvenanceMetadata> {
  const buildTimestamp = predicate.metadata?.buildStartedOn || null;

  const buildkitMeta =
    predicate.metadata?.["https://mobyproject.org/buildkit@v1#metadata"];

  const remoteCommit = getConfigSourceCommit(
    predicate.invocation?.configSource?.digest,
  );
  const localCommit = buildkitMeta?.vcs?.revision;
  const buildConfigDigest = remoteCommit || localCommit || null;
  const buildConfigDigestSource = remoteCommit
    ? "remote"
    : localCommit
    ? "local"
    : null;

  const buildConfigSourceUri =
    predicate.invocation?.configSource?.uri ||
    buildkitMeta?.vcs?.source ||
    null;

  const builderId = predicate.builder?.id || "";
  const buildType = predicate.buildType || "";

  const dockerfileName =
    predicate.invocation?.configSource?.entryPoint || "Dockerfile";

  const dockerfileContents = getEncodedDockerfileContents(
    buildkitMeta?.source?.infos,
    dockerfileName,
  );

  return {
    buildTimestamp,
    buildConfigDigest,
    buildConfigDigestSource,
    attestedManifestDigest,
    attestationManifestDigest,
    buildConfigSourceUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      name: dockerfileName,
      contents: dockerfileContents,
    },
  };
}

async function extractFieldsSlsaV1_0(
  predicate: SlsaPredicateV1_0,
  attestedManifestDigest: string,
  attestationManifestDigest: string,
): Promise<ProvenanceMetadata> {
  const runDetails = predicate.runDetails;
  const buildDefinition = predicate.buildDefinition;

  const buildTimestamp = runDetails?.metadata?.startedOn || null;

  const remoteCommit = getConfigSourceCommit(
    buildDefinition?.externalParameters?.configSource?.digest,
  );
  const localCommit = runDetails?.metadata?.buildkit_metadata?.vcs?.revision;
  const buildConfigDigest = remoteCommit || localCommit || null;
  const buildConfigDigestSource = remoteCommit
    ? "remote"
    : localCommit
    ? "local"
    : null;

  const buildConfigSourceUri =
    buildDefinition?.externalParameters?.configSource?.uri ||
    runDetails?.metadata?.buildkit_metadata?.vcs?.source ||
    null;

  const builderId = runDetails?.builder?.id || "";
  const buildType = buildDefinition?.buildType || "";

  const dockerfileName =
    buildDefinition?.externalParameters?.configSource?.path || "Dockerfile";

  const dockerfileContents = getEncodedDockerfileContents(
    runDetails?.metadata?.buildkit_metadata?.source?.infos,
    dockerfileName,
  );

  return {
    buildTimestamp,
    buildConfigDigest,
    buildConfigDigestSource,
    attestedManifestDigest,
    attestationManifestDigest,
    buildConfigSourceUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      name: dockerfileName,
      contents: dockerfileContents,
    },
  };
}

function getAttestedManifestDigest(statement: InTotoStatement): string | null {
  const digest = statement.subject?.[0]?.digest;
  if (!digest) {
    return null;
  }

  const [algorithm, value] = Object.entries(digest)[0] ?? [];
  if (!algorithm || !value) {
    return null;
  }

  return `${algorithm}:${value}`;
}

function getSlsaProvenanceVersion(
  predicateType?: string,
): SlsaProvenanceVersion | null {
  switch (predicateType) {
    case "https://slsa.dev/provenance/v0.2":
    case "https://slsa.dev/provenance/v1":
      return predicateType;
    default:
      return null;
  }
}

async function parseStatement(
  statement: InTotoStatement,
  attestationManifestDigest: string,
  attestedManifestDigest: string | undefined,
): Promise<ProvenanceMetadata | null> {
  const predicate = statement.predicate;
  if (!predicate) {
    debug("[provenance] No predicate found in in-toto statement");
    return null;
  }

  const resolvedAttestedManifestDigest =
    attestedManifestDigest || getAttestedManifestDigest(statement);
  if (!resolvedAttestedManifestDigest) {
    debug("[provenance] Could not determine the attested manifest digest");
    return null;
  }

  const predicateType = statement.predicateType;
  const version = getSlsaProvenanceVersion(predicateType);
  if (version === null) {
    debug(`[provenance] Unsupported SLSA predicate type: ${predicateType}`);
    return null;
  }

  switch (version) {
    case "https://slsa.dev/provenance/v0.2":
      return extractFieldsSlsaV0_2(
        predicate as SlsaPredicateV0_2,
        resolvedAttestedManifestDigest,
        attestationManifestDigest,
      );
    case "https://slsa.dev/provenance/v1":
      return extractFieldsSlsaV1_0(
        predicate as SlsaPredicateV1_0,
        resolvedAttestedManifestDigest,
        attestationManifestDigest,
      );
    default: {
      const _exhaustiveCheck: never = version;
      return _exhaustiveCheck;
    }
  }
}

export async function parseProvenanceAttestations(
  attestationManifests: ResolvedAttestationManifest[],
): Promise<ProvenanceMetadata[]> {
  const results: ProvenanceMetadata[] = [];

  const sortedManifests = [...attestationManifests].sort((a, b) =>
    a.manifestDigest.localeCompare(b.manifestDigest),
  );

  for (const attestation of sortedManifests) {
    const sortedLayers = [...attestation.manifest.layers].sort((a, b) =>
      a.digest.localeCompare(b.digest),
    );

    for (const layer of sortedLayers) {
      if (results.length >= MAX_ATTESTATIONS_PER_IMAGE) {
        debug(
          `[provenance] Reached max attestation limit (${MAX_ATTESTATIONS_PER_IMAGE}), skipping remaining`,
        );
        return results;
      }

      const inTotoStatement = attestation.inTotoStatements[layer.digest];
      if (!inTotoStatement) {
        continue;
      }

      const parsed = await parseStatement(
        inTotoStatement,
        attestation.manifestDigest,
        attestation.attestedManifestDigest,
      );
      if (parsed) {
        results.push(parsed);
      }
    }
  }

  return results;
}
