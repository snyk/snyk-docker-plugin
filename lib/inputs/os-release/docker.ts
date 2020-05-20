import { Docker } from "../../docker";
import { OsReleaseFilePath } from "../../types";

export async function getOsRelease(
  docker: Docker,
  releasePath: OsReleaseFilePath,
): Promise<string> {
  try {
    return (await docker.catSafe(releasePath)).stdout;
  } catch (error) {
    return "";
  }
}
