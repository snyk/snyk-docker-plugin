import { DockerFileAnalysis } from "../../docker-file";
import { ExtractedLayers } from "../../extractor/types";
import { getOsReleaseStatic as getOsRelease } from "../../inputs/os-release";
import { OsReleaseFilePath } from "../../types";
import { OSRelease } from "../types";
import {
  tryAlpineRelease,
  tryCentosRelease,
  tryDebianVersion,
  tryLsbRelease,
  tryOracleRelease,
  tryOSRelease,
  tryRedHatRelease,
} from "./release-analyzer";

export async function detect(
  extractedLayers: ExtractedLayers,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
): Promise<OSRelease> {
  let osRelease = await tryOSRelease(
    getOsRelease(extractedLayers, OsReleaseFilePath.Linux),
  );

  // Fallback for the case where the same file exists in different location
  // or is a symlink to the other location
  if (!osRelease) {
    osRelease = await tryOSRelease(
      getOsRelease(extractedLayers, OsReleaseFilePath.LinuxFallback),
    );
  }

  // Generic fallback
  if (!osRelease) {
    osRelease = await tryLsbRelease(
      getOsRelease(extractedLayers, OsReleaseFilePath.Lsb),
    );
  }

  // Fallbacks for specific older distributions
  if (!osRelease) {
    osRelease = await tryDebianVersion(
      getOsRelease(extractedLayers, OsReleaseFilePath.Debian),
    );
  }

  if (!osRelease) {
    osRelease = await tryAlpineRelease(
      getOsRelease(extractedLayers, OsReleaseFilePath.Alpine),
    );
  }

  if (!osRelease) {
    osRelease = await tryOracleRelease(
      getOsRelease(extractedLayers, OsReleaseFilePath.Oracle),
    );
  }

  if (!osRelease) {
    osRelease = await tryRedHatRelease(
      getOsRelease(extractedLayers, OsReleaseFilePath.RedHat),
    );
  }

  if (!osRelease) {
    osRelease = await tryCentosRelease(
      getOsRelease(extractedLayers, OsReleaseFilePath.Centos),
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
