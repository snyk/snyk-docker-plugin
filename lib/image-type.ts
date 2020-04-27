import { ImageType } from "./types";

const dockerArchiveIdentifierLength = "docker-archive:".length;

export function getImageType(targetImage: string): ImageType {
  if (targetImage.startsWith("docker-archive:")) {
    return ImageType.DockerArchive;
  }

  return ImageType.Identifier;
}

export function getDockerArchivePath(targetImage: string): string {
  // strip the "docker-archive:" prefix
  return targetImage.substring(dockerArchiveIdentifierLength);
}
