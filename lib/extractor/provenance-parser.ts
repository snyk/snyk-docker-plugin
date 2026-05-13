import * as Debug from "debug";
import { InTotoStatement, RawProvenanceAttestation } from "./types";

const debug = Debug("snyk");

const MAX_ATTESTATIONS_PER_IMAGE = 10;

export interface DockerfileMetadata {
  path: string;
  contents: string | null;
}

export interface ProvenanceAttestation {
  buildTimestamp: string | null;
  commit: string | null;
  manifestDigest: string;
  repoUri: string | null;
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
  statement: InTotoStatement,
): ProvenanceAttestation {
  const buildTimestamp = predicate.metadata?.buildStartedOn || null;

  const buildkitMeta =
    predicate.metadata?.["https://mobyproject.org/buildkit@v1#metadata"];

  const remoteCommit = predicate.invocation?.configSource?.digest?.sha1;
  const localCommit = buildkitMeta?.vcs?.revision;
  const commit = remoteCommit || localCommit || null;

  const repoUri = predicate.invocation?.configSource?.uri || null;

  const builderId = predicate.builder?.id || "";
  const buildType = predicate.buildType || "";

  const dockerfilePath =
    predicate.invocation?.configSource?.entryPoint || "Dockerfile";

  const dockerfileKey = "Dockerfile";
  const dockerfileContents =
    buildkitMeta?.source?.infos?.[0]?.data ||
    buildkitMeta?.source?.locations?.[dockerfileKey]?.data ||
    null;

  return {
    buildTimestamp,
    commit,
    manifestDigest: `sha256:${statement.subject![0].digest!.sha256}`,
    repoUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      path: dockerfilePath,
      contents: dockerfileContents,
    },
  };
}

function extractFieldsSlsa10(
  predicate: SlsaPredicate10,
  statement: InTotoStatement,
): ProvenanceAttestation {
  const runDetails = predicate.runDetails;
  const buildDefinition = predicate.buildDefinition;

  const buildTimestamp = runDetails?.metadata?.startedOn || null;

  const remoteCommit =
    buildDefinition?.externalParameters?.configSource?.digest?.sha1;
  const localCommit = runDetails?.metadata?.buildkit_metadata?.vcs?.revision;
  const commit = remoteCommit || localCommit || null;

  const repoUri =
    buildDefinition?.externalParameters?.configSource?.uri || null;

  const builderId = runDetails?.builder?.id || "";
  const buildType = buildDefinition?.buildType || "";

  const dockerfilePath =
    buildDefinition?.externalParameters?.configSource?.path || "Dockerfile";

  const dockerfileContents =
    runDetails?.metadata?.buildkit_metadata?.source?.infos?.[0]?.data || null;

  return {
    buildTimestamp,
    commit,
    manifestDigest: `sha256:${statement.subject![0].digest!.sha256}`,
    repoUri,
    builderId,
    buildType,
    dockerfileMetadata: {
      path: dockerfilePath,
      contents: dockerfileContents,
    },
  };
}

function parseStatement(
  statement: InTotoStatement,
): ProvenanceAttestation | null {
  const predicate = statement.predicate;
  if (!predicate) {
    debug("[provenance] No predicate found in in-toto statement");
    return null;
  }

  const predicateType = statement.predicateType;

  if (predicateType?.includes("provenance/v0.2")) {
    return extractFieldsSlsa02(predicate as SlsaPredicate02, statement);
  }
  if (predicateType?.includes("provenance/v1")) {
    return extractFieldsSlsa10(predicate as SlsaPredicate10, statement);
  }

  debug(`[provenance] Unsupported SLSA predicate type: ${predicateType}`);
  return null;
}

export function parseProvenanceAttestations(
  attestationManifests: RawProvenanceAttestation[],
): ProvenanceAttestation[] {
  const results: ProvenanceAttestation[] = [];

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

      const parsed = parseStatement(provenanceLayer.inTotoStatement);
      if (parsed) {
        results.push(parsed);
      }
    }
  }

  return results;
}
