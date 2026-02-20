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

export class ParsedImageReference {
  /** Repository path (e.g. nginx, library/nginx) */
  public readonly repository: string;
  /** Registry hostname (e.g. gcr.io, registry-1.docker.io); undefined if none */
  public readonly registry?: string;
  /** Tag (e.g. latest, 1.23.0); undefined if only digest or neither */
  public readonly tag?: string;
  /** Inline digest (e.g. sha256:abc...); undefined if not present */
  public readonly digest?: string;

  constructor(params: {
    repository: string;
    registry?: string;
    tag?: string;
    digest?: string;
  }) {
    this.repository = params.repository;
    this.registry = params.registry;
    this.tag = params.tag;
    this.digest = params.digest;
  }

  /**
   * Rebuilds the image reference string from repository, registry, tag, and digest.
   * Format: [registry/]repository[:tag][@digest]
   */
  public toString(): string {
    let ref = "";
    if (this.registry) {
      ref += this.registry + "/";
    }
    ref += this.repository;
    if (this.tag) {
      ref += ":" + this.tag;
    }
    if (this.digest) {
      ref += "@" + this.digest;
    }
    return ref;
  }

  /**
   * The qualified repository name.
   * This is the registry and repository combined.
   */
  get fullName(): string {
    return this.registry
      ? this.registry + "/" + this.repository
      : this.repository;
  }

  /**
   * Whether the image is from Docker Hub.
   * This is true if the registry is "registry-1.docker.io" or "docker.io" or undefined.
   */
  get isDockerHub(): boolean {
    return (
      this.registry === "registry-1.docker.io" ||
      this.registry === "docker.io" ||
      this.registry === undefined
    );
  }

  /**
   * The registry to use for pulling the image.
   * If the registry is not set, use Docker Hub.
   */
  get registryForPull(): string {
    if (this.isDockerHub || this.registry === undefined) {
      return "registry-1.docker.io";
    }
    return this.registry;
  }

  /**
   * The tail reference to use for pulling the image.
   * If the digest is set, use the digest.
   * If the tag is set, use the tag.
   * If neither are set, use "latest".
   */
  get tailReferenceForPull(): string {
    return this.digest ?? this.tag ?? "latest";
  }

  /**
   * The normalized repository name.
   * If the image is from Docker Hub and the repository does not have a namespace, add the default namespace "library".
   */
  get normalizedRepository(): string {
    if (this.isDockerHub && !this.repository.includes("/")) {
      return "library/" + this.repository;
    }
    return this.repository;
  }
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

  return new ParsedImageReference({
    repository,
    registry,
    tag: tag ?? undefined,
    digest: digest ?? undefined,
  });
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
