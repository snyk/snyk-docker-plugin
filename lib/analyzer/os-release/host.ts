import { DockerFileAnalysis } from "../../docker-file";
import { getOsReleaseHost as getOsRelease } from "../../inputs/os-release";
import { OsReleaseFilePath } from "../../types";
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
): Promise<OSRelease> {
  let osRelease = await getOsRelease(OsReleaseFilePath.Linux).then((release) =>
    tryOSRelease(release),
  );

  // First generic fallback
  if (!osRelease) {
    osRelease = await getOsRelease(OsReleaseFilePath.Lsb).then((release) =>
      tryLsbRelease(release),
    );
  }

  // Fallbacks for specific older distributions
  if (!osRelease) {
    osRelease = await getOsRelease(OsReleaseFilePath.Debian).then((release) =>
      tryDebianVersion(release),
    );
  }

  if (!osRelease) {
    osRelease = await getOsRelease(OsReleaseFilePath.Alpine).then((release) =>
      tryAlpineRelease(release),
    );
  }

  if (!osRelease) {
    osRelease = await getOsRelease(OsReleaseFilePath.Oracle).then((release) =>
      tryOracleRelease(release),
    );
  }

  if (!osRelease) {
    osRelease = await getOsRelease(OsReleaseFilePath.RedHat).then((release) =>
      tryRedHatRelease(release),
    );
  }

  if (!osRelease) {
    if (dockerfileAnalysis && dockerfileAnalysis.baseImage === "scratch") {
      // If the docker file was build from a scratch image
      // then we don't have a known OS
      osRelease = { name: "scratch", version: "0.0", prettyName: "" };
    } else {
      osRelease = { name: "unknown", version: "0.0", prettyName: "" };
    }
  }

  // Oracle Linux identifies itself as "ol"
  if (osRelease.name.trim() === "ol") {
    osRelease.name = "oracle";
  }

  return osRelease;
}
