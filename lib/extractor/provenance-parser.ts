import * as Debug from "debug";
import { InTotoStatement, ProvenanceAttestation } from "./types";

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
  buildConfigCommit: string | null;
  buildConfigCommitSource: "remote" | "local" | null;
  sourceImageDigest: string;
  sourceAttestationDigest: string;
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
        vcs?: { revision?: string };
        source?: {
          infos?: BuildkitSourceInfo[];
        };
      };
    };
  };
}

function getDockerfileContents(
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

function extractFieldsSlsa02(
  predicate: SlsaPredicateV0_2,
  sourceImageDigest: string,
  sourceAttestationDigest: string,
): ProvenanceMetadata {
  const buildTimestamp = predicate.metadata?.buildStartedOn || null;

  const buildkitMeta =
    predicate.metadata?.["https://mobyproject.org/buildkit@v1#metadata"];

  const remoteCommit = getConfigSourceCommit(
    predicate.invocation?.configSource?.digest,
  );
  const localCommit = buildkitMeta?.vcs?.revision;
  const buildConfigCommit = remoteCommit || localCommit || null;
  const buildConfigCommitSource = remoteCommit
    ? "remote"
    : localCommit
    ? "local"
    : null;

  const buildConfigSourceUri = predicate.invocation?.configSource?.uri || null;

  const builderId = predicate.builder?.id || "";
  const buildType = predicate.buildType || "";

  const dockerfileName =
    predicate.invocation?.configSource?.entryPoint || "Dockerfile";

  const dockerfileContents = getDockerfileContents(
    buildkitMeta?.source?.infos,
    dockerfileName,
  );

  return {
    buildTimestamp,
    buildConfigCommit,
    buildConfigCommitSource,
    sourceImageDigest,
    sourceAttestationDigest,
    buildConfigSourceUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      name: dockerfileName,
      contents: dockerfileContents,
    },
  };
}

function extractFieldsSlsa10(
  predicate: SlsaPredicateV1_0,
  sourceImageDigest: string,
  sourceAttestationDigest: string,
): ProvenanceMetadata {
  const runDetails = predicate.runDetails;
  const buildDefinition = predicate.buildDefinition;

  const buildTimestamp = runDetails?.metadata?.startedOn || null;

  const remoteCommit = getConfigSourceCommit(
    buildDefinition?.externalParameters?.configSource?.digest,
  );
  const localCommit = runDetails?.metadata?.buildkit_metadata?.vcs?.revision;
  const buildConfigCommit = remoteCommit || localCommit || null;
  const buildConfigCommitSource = remoteCommit
    ? "remote"
    : localCommit
    ? "local"
    : null;

  const buildConfigSourceUri =
    buildDefinition?.externalParameters?.configSource?.uri || null;

  const builderId = runDetails?.builder?.id || "";
  const buildType = buildDefinition?.buildType || "";

  const dockerfileName =
    buildDefinition?.externalParameters?.configSource?.path || "Dockerfile";

  const dockerfileContents = getDockerfileContents(
    runDetails?.metadata?.buildkit_metadata?.source?.infos,
    dockerfileName,
  );

  return {
    buildTimestamp,
    buildConfigCommit,
    buildConfigCommitSource,
    sourceImageDigest,
    sourceAttestationDigest,
    buildConfigSourceUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      name: dockerfileName,
      contents: dockerfileContents,
    },
  };
}

function getSourceImageDigest(statement: InTotoStatement): string | null {
  const digest = statement.subject?.[0]?.digest;
  if (!digest) {
    return null;
  }

  const [algorithm, value] = Object.entries(digest)[0] ?? []; // Bella todo
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

function parseStatement(
  statement: InTotoStatement,
  sourceAttestationDigest: string,
): ProvenanceMetadata | null {
  const predicate = statement.predicate;
  if (!predicate) {
    debug("[provenance] No predicate found in in-toto statement");
    return null;
  }

  const sourceImageDigest = getSourceImageDigest(statement);
  if (!sourceImageDigest) {
    debug("[provenance] No valid subject digest in in-toto statement");
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
      return extractFieldsSlsa02(
        predicate as SlsaPredicateV0_2,
        sourceImageDigest,
        sourceAttestationDigest,
      );
    case "https://slsa.dev/provenance/v1":
      return extractFieldsSlsa10(
        predicate as SlsaPredicateV1_0,
        sourceImageDigest,
        sourceAttestationDigest,
      );
    default: {
      const _exhaustiveCheck: never = version;
      return _exhaustiveCheck;
    }
  }
}

export function parseProvenanceAttestations(
  attestationManifests: ProvenanceAttestation[],
): ProvenanceMetadata[] {
  const results: ProvenanceMetadata[] = [];

  // Sort by digest so that, when the attestation limit is hit, the selected
  // subset is stable across rebuilds rather than dependent on manifest order.
  const sortedManifests = [...attestationManifests].sort((a, b) =>
    a.attestationManifestDigest.localeCompare(b.attestationManifestDigest),
  );

  for (const manifest of sortedManifests) {
    const sortedLayers = [...manifest.provenanceLayers].sort((a, b) =>
      a.digest.localeCompare(b.digest),
    );

    for (const provenanceLayer of sortedLayers) {
      if (results.length >= MAX_ATTESTATIONS_PER_IMAGE) {
        debug(
          `[provenance] Reached max attestation limit (${MAX_ATTESTATIONS_PER_IMAGE}), skipping remaining`,
        );
        return results;
      }

      if (!provenanceLayer.inTotoStatement) {
        continue;
      }

      const parsed = parseStatement(
        provenanceLayer.inTotoStatement,
        manifest.attestationManifestDigest,
      );
      if (parsed) {
        results.push(parsed);
      }
    }
  }

  return results;
}
