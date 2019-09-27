import { Docker, DockerOptions } from "../../docker";
import { DockerFileAnalysis } from "../../docker-file";
import {
  getAlpineRelease,
  getDebianVersion,
  getLsbRelease,
  getOracleRelease,
  getOsRelease,
  getRedHatRelease,
} from "../../inputs/os-release/docker";
import { OSRelease } from "../types";
import {
  tryAlpineRelease,
  tryDebianVersion,
  tryLsbRelease,
  tryOracleRelease,
  tryOSRelease,
  tryRedHatRelease,
} from "./release-analyzer";

export async function detect(
  targetImage: string,
  dockerfileAnalysis?: DockerFileAnalysis,
  options?: DockerOptions,
): Promise<OSRelease> {
  const docker = new Docker(targetImage, options);

  let osRelease = await getOsRelease(docker).then((release) =>
    tryOSRelease(release),
  );

  // First generic fallback
  if (!osRelease) {
    osRelease = await getLsbRelease(docker).then((release) =>
      tryLsbRelease(release),
    );
  }

  // Fallbacks for specific older distributions
  if (!osRelease) {
    osRelease = await getDebianVersion(docker).then((release) =>
      tryDebianVersion(release),
    );
  }

  if (!osRelease) {
    osRelease = await getAlpineRelease(docker).then((release) =>
      tryAlpineRelease(release),
    );
  }

  if (!osRelease) {
    osRelease = await getOracleRelease(docker).then((release) =>
      tryOracleRelease(release),
    );
  }

  if (!osRelease) {
    osRelease = await getRedHatRelease(docker).then((release) =>
      tryRedHatRelease(release),
    );
  }

  if (!osRelease) {
    if (dockerfileAnalysis && dockerfileAnalysis.baseImage === "scratch") {
      // If the docker file was build from a scratch image
      // then we don't have a known OS

      osRelease = { name: "scratch", version: "0.0" };
    } else {
      throw new Error("Failed to detect OS release");
    }
  }

  // Oracle Linux identifies itself as "ol"
  if (osRelease.name.trim() === "ol") {
    osRelease.name = "oracle";
  }

  return osRelease;
}
