/**
 * Centralized image reference parsing for OCI image names.
 * Uses OCI distribution-style regexes to parse name, registry, tag, and digest.
 */

// Full reference: optional registry, repository path, optional tag, optional digest.
// Capture groups: 1 = name (repo path including optional registry), 2 = tag, 3 = digest.
const imageReferencePattern = String.raw`^((?:(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*|\[(?:[a-fA-F0-9:]+)\])(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*)(?::([a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}))?(?:@([A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][a-fA-F0-9]{32,}))?$`;
const imageReferenceRegex = new RegExp(imageReferencePattern);

// Registry prefix only. Requires '.' or localhost to distinguish registry from repository.
// Capture group 1 = registry hostname (no trailing '/' or '@').
const imageRegistryPattern = String.raw`^((?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+|\[(?:[a-fA-F0-9:]+)\]|localhost)(?::[0-9]+)?)(?:/|@)`;
const imageRegistryRegex = new RegExp(imageRegistryPattern);

export interface ParsedImageReference {
  /** Repository path (e.g. nginx, library/nginx) */
  repository: string;
  /** Registry hostname (e.g. gcr.io, registry-1.docker.io); undefined if none */
  registry?: string;
  /** Tag (e.g. latest, 1.23.0); undefined if only digest or neither */
  tag?: string;
  /** Inline digest (e.g. sha256:abc...); undefined if not present */
  digest?: string;
}

/**
 * Parse an OCI image reference into repository, registry, tag, and digest.
 *
 * @param reference - Image reference string (e.g. nginx:1.23.0@sha256:..., gcr.io/nginx:latest)
 * @returns ParsedImageReference
 * @throws "image name is empty" if reference is empty
 * @throws "image repository contains uppercase letter" if repo path has uppercase
 * @throws "invalid image reference format" if format is invalid
 */
export function parseImageReference(reference: string): ParsedImageReference {
  if (reference === "") {
    throw new Error("image name is empty");
  }

  const groups = imageReferenceRegex.exec(reference);
  if (groups === null) {
    const lowerMatch = imageReferenceRegex.exec(reference.toLowerCase());
    if (lowerMatch !== null) {
      throw new Error("image repository contains uppercase letter");
    }
    throw new Error("invalid image reference format");
  }

  let repository = groups[1];
  const tag = groups[2];
  const digest = groups[3];

  let registry: string | undefined;
  const registryMatch = imageRegistryRegex.exec(repository);
  if (registryMatch !== null) {
    registry = registryMatch[1];
    repository = repository.slice(registry.length + 1);
  }

  return {
    repository,
    registry,
    tag: tag ?? undefined,
    digest: digest ?? undefined,
  };
}

/**
 * Validate a Docker/OCI image reference without throwing.
 *
 * @param reference - Image reference string to validate
 * @returns true if parseImageReference would succeed, false otherwise
 */
export function isValidImageReference(reference: string): boolean {
  try {
    parseImageReference(reference);
    return true;
  } catch {
    return false;
  }
}
