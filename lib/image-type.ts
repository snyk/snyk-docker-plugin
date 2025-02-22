import { normalize as normalizePath } from "path";
import { ImageType } from "./types";

export function getImageType(targetImage: string): ImageType {
  const imageIdentifier = targetImage.split(":")[0];
  switch (imageIdentifier) {
    case "docker-archive":
      return ImageType.DockerArchive;

    case "oci-archive":
      return ImageType.OciArchive;

    case "kaniko-archive":
      return ImageType.KanikoArchive;

    default:
      if (imageIdentifier.endsWith(".tar")) {
        return ImageType.UnspecifiedArchiveType;
      } else {
        return ImageType.Identifier;
      }
  }
}

export function getArchivePath(targetImage: string): string {
  const possibleArchiveTypes = [
    "docker-archive",
    "oci-archive",
    "kaniko-archive",
  ];

  for (const archiveType of possibleArchiveTypes) {
    if (targetImage.startsWith(archiveType)) {
      return normalizePath(targetImage.substring(`${archiveType}:`.length));
    }
  }
  if (targetImage.endsWith(".tar")) {
    return normalizePath(targetImage);
  }

  throw new Error(
    'The provided archive path is missing a prefix, for example "docker-archive:", "oci-archive:" or "kaniko-archive"',
  );
}
