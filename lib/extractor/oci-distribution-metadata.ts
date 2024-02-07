import { parseAll } from "@swimlane/docker-reference";

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
    const ref = parseAll(imageName);
    if (!ref.domain || !ref.repository) {
      return;
    }

    const metadata: OCIDistributionMetadata = {
      registryHost: ref.domain,
      repository: ref.repository,
      manifestDigest,
      indexDigest,
      imageTag: ref.tag,
    };

    if (!ociDistributionMetadataIsValid(metadata)) {
      return;
    }

    return metadata;
  } catch {
    return;
  }
}

function ociDistributionMetadataIsValid(
  data: OCIDistributionMetadata,
): boolean {
  // 255 byte limit is enforced by RFC 1035.
  if (Buffer.byteLength(data.registryHost) > 255) {
    return false;
  }

  // 2048 byte limit is enforced by Snyk for platform stability.
  // Longer strings may be valid, but nothing close to this limit has been observed by Snyk at time of writing.
  if (
    Buffer.byteLength(data.repository) > 2048 ||
    !repositoryNameIsValid(data.repository)
  ) {
    return false;
  }

  if (!digestIsValid(data.manifestDigest)) {
    return false;
  }

  if (data.indexDigest && !digestIsValid(data.indexDigest)) {
    return false;
  }

  if (data.imageTag && !tagIsValid(data.imageTag)) {
    return false;
  }

  return true;
}

// Regular Expression Source: OCI Distribution Spec V1
// https://github.com/opencontainers/distribution-spec/blob/570d0262abe8ec5e59d8e3fbbd7be4bd784b200e/spec.md?plain=1#L141
const repositoryNameIsValid = (name: string) =>
  /^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$/.test(
    name,
  );

// Regular Expression Source: OCI Image Spec V1
// https://github.com/opencontainers/image-spec/blob/d60099175f88c47cd379c4738d158884749ed235/descriptor.md?plain=1#L143
const digestIsValid = (digest: string) => /^sha256:[a-f0-9]{64}$/.test(digest);

// Regular Expression Source: OCI Image Spec V1
// https://github.com/opencontainers/distribution-spec/blob/3940529fe6c0a068290b27fb3cd797cf0528bed6/spec.md?plain=1#L160
const tagIsValid = (tag: string) =>
  /^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$/.test(tag);
