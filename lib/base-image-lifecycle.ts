/**
 * Base Image End-of-Life (EOL) lifecycle status detection.
 *
 * Provides programmatic access to the EOL/lifecycle status of a detected
 * base image OS, based on a lookup table of well-known Linux distributions
 * and their official end-of-life dates.
 */

export type LifecycleStatus = "eol" | "maintained" | "unknown";

export interface BaseImageLifecycleStatus {
  /** Whether the base image OS version has reached end-of-life. */
  isEol: boolean;
  /** Human-readable lifecycle status of the base image OS version. */
  lifecycleStatus: LifecycleStatus;
  /**
   * The official end-of-life date for the base image OS version, as an ISO
   * 8601 date string (YYYY-MM-DD), if known. Absent when status is "unknown".
   */
  endOfLifeDate?: string;
}

/**
 * EOL data keyed by `"<distroName>@<version>"`.
 * Versions are the normalised minor version string used by each distro's
 * release files (e.g. "20.04" for Ubuntu, "3.18" for Alpine, "11" for
 * Debian). Dates are ISO 8601 (YYYY-MM-DD) standard end-of-life dates.
 *
 * Sources:
 *  - Ubuntu:       https://ubuntu.com/about/release-cycle
 *  - Debian:       https://www.debian.org/releases/
 *  - Alpine:       https://alpinelinux.org/releases/
 *  - Amazon Linux: https://aws.amazon.com/amazon-linux-ami/faqs/
 *  - RHEL:         https://access.redhat.com/support/policy/updates/errata/
 *  - CentOS:       https://wiki.centos.org/About/Product
 *  - Oracle Linux: https://www.oracle.com/us/support/library/elsp-lifetime-069338.pdf
 */
const EOL_DATES: Record<string, string> = {
  // Ubuntu LTS
  "ubuntu@14.04": "2019-04-25",
  "ubuntu@16.04": "2021-04-30",
  "ubuntu@18.04": "2023-04-30",
  "ubuntu@20.04": "2025-04-30",
  "ubuntu@22.04": "2027-04-30",
  "ubuntu@24.04": "2029-04-30",
  "ubuntu@24.10": "2025-07-11",

  // Debian
  "debian@8": "2018-06-30",
  "debian@9": "2022-06-30",
  "debian@10": "2024-06-30",
  "debian@11": "2026-08-15",
  "debian@12": "2028-06-30",

  // Alpine Linux (keyed by major.minor; patch is stripped during normalisation)
  "alpine@3.13": "2022-11-01",
  "alpine@3.14": "2023-05-01",
  "alpine@3.15": "2023-11-01",
  "alpine@3.16": "2024-05-23",
  "alpine@3.17": "2024-11-22",
  "alpine@3.18": "2025-05-09",
  "alpine@3.19": "2025-11-01",
  "alpine@3.20": "2026-04-01",
  "alpine@3.21": "2026-11-01",

  // Amazon Linux
  "amzn@1": "2023-12-31",
  "amzn@2": "2025-06-30",
  "amzn@2022": "2027-12-31",
  "amzn@2023": "2027-12-31",
  "amazon@1": "2023-12-31",
  "amazon@2": "2025-06-30",
  "amazon@2022": "2027-12-31",
  "amazon@2023": "2027-12-31",

  // Red Hat Enterprise Linux
  "rhel@6": "2020-11-30",
  "rhel@7": "2024-06-30",
  "rhel@8": "2029-05-31",
  "rhel@9": "2032-05-31",

  // CentOS
  "centos@6": "2020-11-30",
  "centos@7": "2024-06-30",
  "centos@8": "2021-12-31",

  // Oracle Linux
  "ol@6": "2021-03-01",
  "ol@7": "2024-12-31",
  "ol@8": "2029-07-01",
  "ol@9": "2032-07-01",
  "oracle@6": "2021-03-01",
  "oracle@7": "2024-12-31",
  "oracle@8": "2029-07-01",
  "oracle@9": "2032-07-01",
};

/**
 * Normalise the version string so it matches the key used in `EOL_DATES`.
 *
 * - Ubuntu / Debian: use as-is (e.g. "20.04", "11").
 * - Alpine: strip patch component ("3.18.6" → "3.18").
 * - Amazon Linux / RHEL / CentOS: use major component only ("7.9" → "7").
 */
function normaliseVersion(distro: string, version: string): string {
  const lower = distro.toLowerCase();
  if (lower === "alpine") {
    // "3.18.6" → "3.18"
    const parts = version.split(".");
    return parts.length >= 2 ? `${parts[0]}.${parts[1]}` : version;
  }
  if (
    lower === "rhel" ||
    lower === "centos" ||
    lower === "ol" ||
    lower === "oracle" ||
    lower === "amzn" ||
    lower === "amazon"
  ) {
    // "7.9" → "7"
    return version.split(".")[0];
  }
  return version;
}

/**
 * Determine the lifecycle status of a container base image given the OS name
 * and version as detected from the image's release files.
 *
 * @param distro  - OS identifier as detected (e.g. "ubuntu", "alpine", "debian").
 * @param version - OS version string as detected (e.g. "20.04", "3.18.6", "11").
 * @param referenceDate - Optional ISO date string to evaluate EOL against.
 *   Defaults to the current date. Useful for deterministic testing.
 * @returns A {@link BaseImageLifecycleStatus} object.
 */
export function getBaseImageLifecycleStatus(
  distro: string,
  version: string,
  referenceDate?: string,
): BaseImageLifecycleStatus {
  const normalisedDistro = distro.toLowerCase();
  const normalisedVersion = normaliseVersion(normalisedDistro, version);
  const key = `${normalisedDistro}@${normalisedVersion}`;

  const eolDate = EOL_DATES[key];
  if (eolDate === undefined) {
    return { isEol: false, lifecycleStatus: "unknown" };
  }

  const now = referenceDate ? new Date(referenceDate) : new Date();
  const eol = new Date(eolDate);
  const isEol = now > eol;

  return {
    isEol,
    lifecycleStatus: isEol ? "eol" : "maintained",
    endOfLifeDate: eolDate,
  };
}
