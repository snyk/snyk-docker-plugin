import { ImageTransport } from "./types";

export function getImageTransport(targetImage: string): ImageTransport {
  if (targetImage.startsWith("docker-archive:")) {
    return ImageTransport.DockerArchive;
  }

  return ImageTransport.ContainerRegistry;
}

export function getDockerArchivePath(targetImage: string): string {
  return targetImage; // TODO: strip the "docker-archive:" at the start
}
