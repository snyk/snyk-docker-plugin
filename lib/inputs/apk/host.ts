import { readFile } from "../../docker-file";

export async function getApkDbFileContent(): Promise<string> {
  try {
    return await readFile("/lib/apk/db/installed");
  } catch (error) {
    return "";
  }
}
