import { valid } from "semver";
import { Binary } from "../../../analyzer/types";
import { Docker, DockerOptions } from "../../../docker";

export { extract, installedByPackageManager };

async function extract(
  targetImage: string,
  options?: DockerOptions,
): Promise<Binary | null> {
  try {
    const binaryVersion = (
      await new Docker(targetImage, options).runSafe("node", ["--version"])
    ).stdout;
    return parseNodeBinary(binaryVersion);
  } catch (error) {
    throw new Error(error.stderr);
  }
}

function parseNodeBinary(version: string) {
  const nodeVersion = valid(version && version.trim());
  if (!nodeVersion) {
    return null;
  }
  return {
    name: "node",
    version: nodeVersion,
  };
}

const packageNames = ["node", "nodejs"];

function installedByPackageManager(installedPackages: string[]): boolean {
  return (
    installedPackages.filter((pkg) => packageNames.indexOf(pkg) > -1).length > 0
  );
}
