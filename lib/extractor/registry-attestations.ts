import {
  getAttestationManifest,
  getLayer,
} from "@snyk/docker-registry-v2-client";
import { createHash } from "crypto";

import { InTotoStatement, ResolvedAttestationManifest } from "./types";

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
  } catch {
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
    // An attestation manifest can carry several in-toto statements sharing the same
    // mediaType (e.g. SLSA provenance AND an SPDX SBOM). The `in-toto.io/predicate-type`
    // annotation is what distinguishes them, so use it to fetch only provenance layers and
    // avoid downloading (potentially large) SBOM blobs we'd discard downstream. When the
    // annotation is absent (a tool that didn't set it) we fall back to fetching and let
    // the provenance parser decide, so we never miss a genuine provenance statement.
    const predicateType = layer.annotations?.[PREDICATE_TYPE_ANNOTATION];
    if (predicateType && !predicateType.startsWith(SLSA_PROVENANCE_PREFIX)) {
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
    } catch {
      // Skip a layer we can't fetch or parse; other layers may still be usable.
    }
  }

  if (Object.keys(inTotoStatements).length === 0) {
    return [];
  }

  return [
    {
      // NOTE: the client doesn't expose the descriptor digest for the fetched
      // attestation manifest, so we derive a stable digest from its content. This is
      // used as `source_attestation_digest`; if the exact registry descriptor digest is
      // required, resolve it from the image index's attestation-manifest descriptor.
      manifestDigest:
        "sha256:" +
        createHash("sha256").update(JSON.stringify(manifest)).digest("hex"),
      manifest: manifest as unknown as ResolvedAttestationManifest["manifest"],
      inTotoStatements,
    },
  ];
}

/** Parses an "os/arch[/variant]" platform string into the registry client's shape. */
export function parsePlatform(
  platform?: string,
): { os: string; architecture: string; variant?: string } | undefined {
  if (!platform) {
    return undefined;
  }
  const [os, architecture, variant] = platform.split("/");
  if (!os || !architecture) {
    return undefined;
  }
  return { os, architecture, variant };
}
