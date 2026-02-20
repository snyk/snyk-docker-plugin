import { parseImageReference } from "../image-reference";

export interface OCIDistributionMetadata {
  // Must be a valid host, including port if one was used to pull the image.
  // Max size: 255 bytes.
  registryHost: string;
  // Must be a valid OCI repository namespace.
  // Max size: 2048 bytes.
  repository: string;
  // Must match sha256:[a-f0-9]{64} (https://github.com/opencontainers/image-spec/blob/d60099175f88c47cd379c4738d158884749ed235/descriptor.md?plain=1#L143).
  // Max size: 64 bytes.
  manifestDigest: string;
  // (Optional) Must match sha256:[a-f0-9]{64} (https://github.com/opencontainers/image-spec/blob/d60099175f88c47cd379c4738d158884749ed235/descriptor.md?plain=1#L143).
  // Max size: 64 bytes.
  indexDigest?: string;
  // (Optional) Must match [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127} (https://github.com/opencontainers/distribution-spec/blob/3940529fe6c0a068290b27fb3cd797cf0528bed6/spec.md?plain=1#L160).
  // Max size: 127 bytes.
  imageTag?: string;
}

interface OCIDistributionMetadataConstructorInput {
  imageName: string;
  manifestDigest: string;
  indexDigest?: string;
}

export function constructOCIDisributionMetadata({
  imageName,
  manifestDigest,
  indexDigest,
}: OCIDistributionMetadataConstructorInput):
  | OCIDistributionMetadata
  | undefined {
  try {
    const parsed = parseImageReference(imageName);
    // Extract the registry hostname, using "docker.io" as the default for Docker Hub images.
    // Note this is different from registryForPull, which defaults to "registry-1.docker.io" for Docker Hub images.
    const hostname = parsed.registry ? parsed.registry : "docker.io";
    const metadata: OCIDistributionMetadata = {
      registryHost: hostname,
      repository: parsed.normalizedRepository,
      manifestDigest,
      indexDigest,
      imageTag: parsed.tag,
    };

    // 255 byte limit is enforced by RFC 1035.
    if (Buffer.byteLength(metadata.registryHost) > 255) {
      return;
    }

    // 2048 byte limit is enforced by Snyk for platform stability.
    // Longer strings may be valid, but nothing close to this limit has been observed by Snyk at time of writing.
    if (Buffer.byteLength(metadata.repository) > 2048) {
      return;
    }

    return metadata;
  } catch {
    return;
  }
}
