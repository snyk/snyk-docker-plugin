import { readFile } from "../../docker-file";
import { OsReleaseFilePath } from "../../types";

export async function getOsRelease(
  releasePath: OsReleaseFilePath,
): Promise<string> {
  try {
    return await readFile(releasePath);
  } catch (error) {
    throw new Error(error);
  }
}
