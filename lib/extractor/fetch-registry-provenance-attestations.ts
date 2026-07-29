import {
  getAttestationManifest,
  getLayer,
} from "@snyk/docker-registry-v2-client";
import * as Debug from "debug";

import { getErrorMessage } from "../error-utils";
import {
  getOciPlatformInfoFromOptionString,
  MAX_JSON_SIZE_BYTES,
} from "./oci-archive/layer";
import {
  InTotoStatement,
  OciArchiveManifest,
  ResolvedAttestationManifest,
} from "./types";

const debug = Debug("snyk");

const MEDIATYPE_IN_TOTO = "application/vnd.in-toto+json";
const PREDICATE_TYPE_ANNOTATION = "in-toto.io/predicate-type";
const SLSA_PROVENANCE_PREFIX = "https://slsa.dev/provenance/";

interface RegistryImageRef {
  registryBase: string;
  repo: string;
  imageReference: string; // tag or digest
  username?: string;
  password?: string;
  platform?: { os: string; architecture: string; variant?: string };
}

// Fetches provenance attestations for an image directly from its source registry.
export async function fetchAttestationsFromRegistry(
  ref: RegistryImageRef,
): Promise<ResolvedAttestationManifest[]> {
  const { registryBase, repo, imageReference, username, password, platform } =
    ref;

  let manifest;
  try {
    manifest = await getAttestationManifest(
      registryBase,
      repo,
      imageReference,
      username,
      password,
      undefined,
      platform,
    );
  } catch (error) {
    debug(
      `[provenance] failed to fetch attestation manifest for ${repo}@${imageReference}: ${getErrorMessage(
        error,
      )}`,
    );
    return [];
  }

  if (
    !manifest ||
    !Array.isArray(manifest.layers) ||
    manifest.layers.length === 0
  ) {
    return [];
  }

  const inTotoStatements: Record<string, InTotoStatement> = {};
  for (const layer of manifest.layers) {
    if (layer.mediaType !== MEDIATYPE_IN_TOTO) {
      continue;
    }

    const predicateType = layer.annotations?.[PREDICATE_TYPE_ANNOTATION];
    if (predicateType && !predicateType.startsWith(SLSA_PROVENANCE_PREFIX)) {
      continue;
    }

    if (typeof layer.size === "number" && layer.size > MAX_JSON_SIZE_BYTES) {
      debug(
        `[provenance] skipping oversized attestation layer ${layer.digest} (${layer.size} bytes > ${MAX_JSON_SIZE_BYTES})`,
      );
      continue;
    }
    try {
      const blob = await getLayer(
        registryBase,
        repo,
        layer.digest,
        username,
        password,
      );
      inTotoStatements[layer.digest] = JSON.parse(
        blob.toString("utf-8"),
      ) as InTotoStatement;
    } catch (error) {
      debug(
        `[provenance] skipping layer ${layer.digest}: ${getErrorMessage(
          error,
        )}`,
      );
    }
  }

  if (Object.keys(inTotoStatements).length === 0) {
    return [];
  }

  if (!manifest.manifestDigest) {
    debug(
      `[provenance] no descriptor digest for attestation manifest ${repo}@${imageReference}; skipping`,
    );
    return [];
  }

  const resolvedManifest: OciArchiveManifest = {
    schemaVersion: String(manifest.schemaVersion),
    mediaType: manifest.mediaType,
    config: { digest: manifest.config.digest },
    layers: manifest.layers.map((layer) => ({
      digest: layer.digest,
      mediaType: layer.mediaType,
      size: layer.size,
      annotations: layer.annotations,
    })),
  };

  return [
    {
      manifestDigest: manifest.manifestDigest,
      manifest: resolvedManifest,
      inTotoStatements,
    },
  ];
}

export function parsePlatform(
  platform?: string,
): { os: string; architecture: string; variant?: string } | undefined {
  if (!platform) {
    return undefined;
  }

  const info = getOciPlatformInfoFromOptionString(platform);
  if (!info.os || !info.architecture) {
    return undefined;
  }
  return {
    os: info.os,
    architecture: info.architecture,
    variant: info.variant,
  };
}
