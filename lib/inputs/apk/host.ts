import { readFile } from "../../docker-file";

export function getApkDbFileContent(): Promise<string> {
  return readFile("/lib/apk/db/installed");
}
