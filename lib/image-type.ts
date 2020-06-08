import { ImageType } from "./types";

export function getImageType(targetImage: string): ImageType {
  const imageIdentifier = targetImage.split(":")[0];
  switch (imageIdentifier) {
    case "docker-archive":
      return ImageType.DockerArchive;

    case "oci-archive":
      return ImageType.OciArchive;

    default:
      return ImageType.Identifier;
  }
}

export function getArchivePath(targetImage: string): string {
  // strip the "docker-archive:" or "oci-archive:" prefix

  const path = targetImage.split(":")[1];
  if (!path) {
    throw new Error(
      'The provided archive path is missing image specific prefix, eg."docker-archive:" or "oci-archive:"',
    );
  }

  return path;
}
