import { readFile } from "../../docker-file";

export function getAptDbFileContent(): Promise<{
  dpkgFile: string;
  extFile: string;
}> {
  return Promise.all([
    readFile("/var/lib/dpkg/status"),
    readFile("/var/lib/apt/extended_states"),
  ]).then((fileContents) => ({
    dpkgFile: fileContents[0],
    extFile: fileContents[1],
  }));
}
