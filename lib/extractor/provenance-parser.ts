import * as Debug from "debug";
import { InTotoStatement, ProvenanceAttestation } from "./types";

const debug = Debug("snyk");

const MAX_ATTESTATIONS_PER_IMAGE = 10;

export interface DockerfileMetadata {
  name: string;
  contents: string | null;
}

export interface ProvenanceMetadata {
  buildTimestamp: string | null;
  buildConfigCommit: string | null;
  sourceImageDigest: string;
  sourceAttestationDigest: string;
  repositoryUri: string | null;
  builderId: string;
  buildType: string;
  dockerfileMetadata: DockerfileMetadata;
}

interface SlsaPredicate02 {
  builder?: { id?: string };
  buildType?: string;
  metadata?: {
    buildStartedOn?: string;
    "https://mobyproject.org/buildkit@v1#metadata"?: {
      vcs?: { source?: string; revision?: string };
      source?: {
        infos?: Array<{ data?: string }>;
        locations?: Record<string, { data?: string }>;
      };
    };
  };
  invocation?: {
    configSource?: {
      uri?: string;
      digest?: { sha1?: string };
      entryPoint?: string;
    };
  };
}

interface SlsaPredicate10 {
  buildDefinition?: {
    buildType?: string;
    externalParameters?: {
      configSource?: {
        uri?: string;
        digest?: { sha1?: string };
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
          infos?: Array<{ data?: string }>;
        };
      };
    };
  };
}

function extractFieldsSlsa02(
  predicate: SlsaPredicate02,
  sourceImageDigest: string,
  sourceAttestationDigest: string,
): ProvenanceMetadata {
  const buildTimestamp = predicate.metadata?.buildStartedOn || null;

  const buildkitMeta =
    predicate.metadata?.["https://mobyproject.org/buildkit@v1#metadata"];

  const remoteCommit = predicate.invocation?.configSource?.digest?.sha1;
  const localCommit = buildkitMeta?.vcs?.revision;
  const buildConfigCommit = remoteCommit || localCommit || null;

  const repositoryUri = predicate.invocation?.configSource?.uri || null;

  const builderId = predicate.builder?.id || "";
  const buildType = predicate.buildType || "";

  const dockerfileName =
    predicate.invocation?.configSource?.entryPoint || "Dockerfile";

  const dockerfileKey = "Dockerfile";
  const dockerfileContents =
    buildkitMeta?.source?.infos?.[0]?.data ||
    buildkitMeta?.source?.locations?.[dockerfileKey]?.data ||
    null;

  return {
    buildTimestamp,
    buildConfigCommit,
    sourceImageDigest,
    sourceAttestationDigest,
    repositoryUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      name: dockerfileName,
      contents: dockerfileContents,
    },
  };
}

function extractFieldsSlsa10(
  predicate: SlsaPredicate10,
  sourceImageDigest: string,
  sourceAttestationDigest: string,
): ProvenanceMetadata {
  const runDetails = predicate.runDetails;
  const buildDefinition = predicate.buildDefinition;

  const buildTimestamp = runDetails?.metadata?.startedOn || null;

  const remoteCommit =
    buildDefinition?.externalParameters?.configSource?.digest?.sha1;
  const localCommit = runDetails?.metadata?.buildkit_metadata?.vcs?.revision;
  const buildConfigCommit = remoteCommit || localCommit || null;

  const repositoryUri =
    buildDefinition?.externalParameters?.configSource?.uri || null;

  const builderId = runDetails?.builder?.id || "";
  const buildType = buildDefinition?.buildType || "";

  const dockerfileName =
    buildDefinition?.externalParameters?.configSource?.path || "Dockerfile";

  const dockerfileContents =
    runDetails?.metadata?.buildkit_metadata?.source?.infos?.[0]?.data || null;

  return {
    buildTimestamp,
    buildConfigCommit,
    sourceImageDigest,
    sourceAttestationDigest,
    repositoryUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      name: dockerfileName,
      contents: dockerfileContents,
    },
  };
}

function getSourceImageDigest(statement: InTotoStatement): string | null {
  const sha256 = statement.subject?.[0]?.digest?.sha256;
  return sha256 ? `sha256:${sha256}` : null;
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

  if (predicateType?.includes("provenance/v0.2")) {
    return extractFieldsSlsa02(
      predicate as SlsaPredicate02,
      sourceImageDigest,
      sourceAttestationDigest,
    );
  }
  if (predicateType?.includes("provenance/v1")) {
    return extractFieldsSlsa10(
      predicate as SlsaPredicate10,
      sourceImageDigest,
      sourceAttestationDigest,
    );
  }

  debug(`[provenance] Unsupported SLSA predicate type: ${predicateType}`);
  return null;
}

export function parseProvenanceAttestations(
  attestationManifests: ProvenanceAttestation[],
): ProvenanceMetadata[] {
  const results: ProvenanceMetadata[] = [];

  for (const manifest of attestationManifests) {
    for (const provenanceLayer of manifest.provenanceLayers) {
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
