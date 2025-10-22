import * as Debug from "debug";
import { normalize as normalizePath } from "path";

import { DockerFileAnalysis } from "../../dockerfile/types";
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

const debug = Debug("snyk");

type OsReleaseHandler = (text: string) => Promise<OSRelease | null>;

/**
 * Checks if a Chisel manifest exists in the extracted layers.
 * Chisel is Ubuntu's tool for creating minimal container images.
 *
 * @param extractedLayers - Layers extracted from the Docker image
 * @returns true if Chisel manifest.wall file is present
 */
function hasChiselManifest(extractedLayers: ExtractedLayers): boolean {
  const manifestPath = normalizePath("/var/lib/chisel/manifest.wall");
  return manifestPath in extractedLayers;
}

const releaseDetectors: Record<OsReleaseFilePath, OsReleaseHandler> = {
  [OsReleaseFilePath.Linux]: tryOSRelease,
  // Fallback for the case where the same file exists in different location or is a symlink to the other location
  [OsReleaseFilePath.LinuxFallback]: tryOSRelease,
  // Generic fallback
  [OsReleaseFilePath.Lsb]: tryLsbRelease,
  // Fallbacks for specific older distributions
  [OsReleaseFilePath.Debian]: tryDebianVersion,
  [OsReleaseFilePath.Alpine]: tryAlpineRelease,
  [OsReleaseFilePath.Oracle]: tryOracleRelease,
  [OsReleaseFilePath.RedHat]: tryRedHatRelease,
  [OsReleaseFilePath.Centos]: tryCentosRelease,
};

export async function detect(
  extractedLayers: ExtractedLayers,
  dockerfileAnalysis: DockerFileAnalysis | undefined,
): Promise<OSRelease> {
  /**
   * We want to detect whether the OS release file existed, but it just could not be parsed successfully.
   * This is so that we can distinguish between images with multiple "os-release" files - some of them
   * may fail to parse while others will succeed. This will depend purely on the order of our handlers.
   * We want to run all handlers and only then decide if detection succeeded or not.
   */
  let hadOsReleaseFile = false;

  let osRelease: OSRelease | null = null;
  for (const [type, handler] of Object.entries(releaseDetectors)) {
    const osReleaseFile = getOsRelease(
      extractedLayers,
      type as OsReleaseFilePath,
    );
    if (!osReleaseFile) {
      continue;
    }

    hadOsReleaseFile = true;
    try {
      osRelease = await handler(osReleaseFile);
    } catch (err) {
      debug(`Malformed OS release file: ${err.message}`);
    }
    if (osRelease) {
      break;
    }
  }

  if (!osRelease && hadOsReleaseFile) {
    throw new Error("Failed to parse OS release file");
  }

  if (!osRelease) {
    // Check if this is a Chisel image without OS release information
    const isChiselImage = hasChiselManifest(extractedLayers);
    
    if (isChiselImage) {
      // Chisel images detected but OS version could not be determined
      // This happens when ultra-minimal Chisel slices are used without base-files_release-info
      debug(
        "Chisel manifest found at /var/lib/chisel/manifest.wall but no OS release files detected",
      );
      
      // Set OS name to "chisel" so downstream systems can identify these images
      // note we only do this to alert the user that they are missing release info
      // when they have release info, we identify the image with that instead
      osRelease = { name: "chisel", version: "0.0", prettyName: "" };
    } else if (dockerfileAnalysis && dockerfileAnalysis.baseImage === "scratch") {
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

  // Support round version. ie change SLES 15 to SLES 15.0
  if (
    osRelease.name.trim() === "sles" &&
    osRelease.version &&
    !osRelease.version.includes(".")
  ) {
    osRelease.version += ".0";
  }

  return osRelease;
}
