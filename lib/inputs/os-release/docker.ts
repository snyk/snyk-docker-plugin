import { Docker } from "../../docker";

export function getOsRelease(docker: Docker): Promise<string> {
  return getFileContent(docker, "/etc/os-release");
}

export function getLsbRelease(docker: Docker): Promise<string> {
  return getFileContent(docker, "/etc/lsb-release");
}

export function getDebianVersion(docker: Docker): Promise<string> {
  return getFileContent(docker, "/etc/debian_version");
}

export function getAlpineRelease(docker: Docker): Promise<string> {
  return getFileContent(docker, "/etc/alpine-release");
}

export function getRedHatRelease(docker: Docker): Promise<string> {
  return getFileContent(docker, "/etc/redhat-release");
}

export function getOracleRelease(docker: Docker): Promise<string> {
  return getFileContent(docker, "/etc/oracle-release");
}

async function getFileContent(
  docker: Docker,
  release: string,
): Promise<string> {
  try {
    return (await docker.catSafe(release)).stdout;
  } catch (error) {
    throw new Error(error.stderr);
  }
}
