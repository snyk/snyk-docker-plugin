import { contentTypes, getManifest } from "@snyk/docker-registry-v2-client";
import * as Debug from "debug";

import { getErrorMessage } from "../error-utils";
import { REGISTRY_REQUEST_TIMEOUTS } from "./fetch-registry-provenance-attestations";

const debug = Debug("snyk");

// Same Accept header the Docker Registry Agent uses, so OCI indexes are returned as-is.
const ACCEPT_MANIFEST = [
  contentTypes.OCI_INDEX_V1,
  contentTypes.OCI_MANIFEST_V1,
  contentTypes.MANIFEST_LIST_V2,
  contentTypes.MANIFEST_V2,
].join(",");

// Registries list these architectures with a variant that local images often omit.
const DEFAULT_VARIANTS: Record<string, string> = { arm64: "v8", arm: "v7" };

type Platform = { os: string; architecture: string; variant?: string };

interface RegistryDigestRef {
  registryBase: string;
  repo: string;
  imageReference: string; // tag or digest
  username?: string;
  password?: string;
  platform?: Platform;
  // The config digest (image ID) of the image that was actually scanned.
  expectedConfigDigest: string;
}

export interface DistributionDigests {
  manifest: string;
  index?: string;
}

/**
 * Looks up the manifest and index digests for the scanned image in its registry.
 * Digests are returned only when the registry's manifest for the platform points
 * at the same config digest that was scanned; otherwise (local-only or stale
 * image, other platform, auth/network failure) nothing is returned.
 */
export async function fetchDistributionDigestsFromRegistry(
  ref: RegistryDigestRef,
): Promise<DistributionDigests | undefined> {
  const { registryBase, repo, imageReference, username, password } = ref;

  for (const platform of platformCandidates(ref.platform)) {
    try {
      const manifest = await getManifest(
        registryBase,
        repo,
        imageReference,
        username,
        password,
        { acceptManifest: ACCEPT_MANIFEST, ...REGISTRY_REQUEST_TIMEOUTS },
        platform,
      );

      if (manifest?.config?.digest !== ref.expectedConfigDigest) {
        debug(
          `[distribution-digests] registry manifest for ${repo}@${imageReference} does not match the scanned image; skipping`,
        );
        return undefined;
      }
      if (!manifest.manifestDigest) {
        return undefined;
      }
      return { manifest: manifest.manifestDigest, index: manifest.indexDigest };
    } catch (error) {
      debug(
        `[distribution-digests] failed to fetch manifest for ${repo}@${imageReference}: ${getErrorMessage(
          error,
        )}`,
      );
    }
  }
  return undefined;
}

function platformCandidates(platform?: Platform): Array<Platform | undefined> {
  const defaultVariant = platform && DEFAULT_VARIANTS[platform.architecture];
  if (platform && !platform.variant && defaultVariant) {
    return [platform, { ...platform, variant: defaultVariant }];
  }
  return [platform];
}
