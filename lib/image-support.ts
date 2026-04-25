import { ImageSupportFact, ImageUnsupportedReason } from "./facts";
import { OSRelease } from "./analyzer/types";

/**
 * URL pointing to Snyk Container's supported Linux distributions documentation.
 * Included in unsupported-image messages so consumers can redirect users.
 */
export const SUPPORTED_DISTROS_URL =
  "https://docs.snyk.io/products/snyk-container/snyk-container-security-basics/supported-operating-system-distributions";

/**
 * OS names that the detect() function emits when no recognised distribution was found.
 * These sentinels are used by computeImageSupport() to classify unsupported images.
 */
export const UNSUPPORTED_OS_NAMES = new Set(["unknown"]);

export interface ComputeImageSupportInput {
  targetImage: string;
  osRelease: OSRelease;
  packageFormat: string;
  hasAnyPackages: boolean;
  hasApplicationDependencies?: boolean;
}

/**
 * Derives the support status for an image based on OS detection and package analysis results.
 *
 * Rules (in priority order):
 * 1. Windows base image → unsupported / windows-image
 * 2. Unknown OS (no recognizable os-release) → unsupported / unknown-os
 * 3. Scratch image (FROM scratch with no packages, and no app deps) → unsupported / scratch-image
 * 4. OS detected but no package DB found (packageFormat is "linux" with no packages) → unsupported / no-package-manager
 * 5. Everything else → supported
 */
export function computeImageSupport(
  input: ComputeImageSupportInput,
): ImageSupportFact["data"] {
  const {
    targetImage,
    osRelease,
    packageFormat,
    hasAnyPackages,
    hasApplicationDependencies,
  } = input;

  const detectedOs = {
    name: osRelease.name,
    version: osRelease.version,
    prettyName: osRelease.prettyName,
  };

  const buildUnsupported = (
    reason: ImageUnsupportedReason,
  ): ImageSupportFact["data"] => {
    const displayName = osRelease.prettyName || osRelease.name;
    return {
      status: "unsupported",
      reason,
      detectedOs,
      targetImage,
      message: `Snyk Container does not support this image (${reason}). Detected OS: ${displayName}. See ${SUPPORTED_DISTROS_URL}`,
    };
  };

  // Windows image — checked first regardless of other signals
  if (osRelease.name.toLowerCase() === "windows") {
    return buildUnsupported("windows-image");
  }

  // Unknown OS — no os-release file found and no scratch/chisel hint
  if (UNSUPPORTED_OS_NAMES.has(osRelease.name)) {
    return buildUnsupported("unknown-os");
  }

  // Scratch image — only mark unsupported when there are also no application deps;
  // a scratch image with only app-vulns is intentional (e.g. distroless-like Go binary)
  if (osRelease.name === "scratch" && !hasApplicationDependencies) {
    return buildUnsupported("scratch-image");
  }

  // OS detected but no package manager DB found
  // packageFormat "linux" is the sentinel emitted by parseAnalysisResults when no
  // package manager analysis succeeded (AnalysisType.Linux fallback).
  if (packageFormat === "linux" && !hasAnyPackages && osRelease.name !== "scratch") {
    return buildUnsupported("no-package-manager");
  }

  return { status: "supported", detectedOs, targetImage };
}
