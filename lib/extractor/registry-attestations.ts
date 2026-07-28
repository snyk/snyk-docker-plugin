import {
  getAttestationManifest,
  getLayer,
} from "@snyk/docker-registry-v2-client";
import { createHash } from "crypto";

import { InTotoStatement, ResolvedAttestationManifest } from "./types";

const MEDIATYPE_IN_TOTO = "application/vnd.in-toto+json";

interface RegistryImageRef {
  registryBase: string;
  repo: string;
  imageReference: string; // tag or digest
  username?: string;
  password?: string;
  platform?: { os: string; architecture: string; variant?: string };
}

/**
 * Fetches provenance attestations for an image directly from its source registry.
 *
 * When an image is obtained via `docker pull` (or exported with `docker save` on the
 * classic image store), the attestation manifest — a `platform: unknown/unknown` sidecar
 * in the image index — is dropped, so a registry-reference scan never sees provenance.
 * This fetches the attestation manifest and its in-toto layers straight from the registry
 * so provenance can be surfaced regardless of how the image reached the daemon.
 *
 * Best-effort: returns [] on any failure (no attestation present, registry doesn't
 * support the referrers/attestation lookup, auth or network error) so it never breaks
 * a scan.
 */
export async function fetchAttestationsFromRegistry(
  ref: RegistryImageRef,
): Promise<ResolvedAttestationManifest[]> {
  const { registryBase, repo, imageReference, username, password, platform } = ref;

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
