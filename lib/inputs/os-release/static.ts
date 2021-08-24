import { normalize as normalizePath } from "path";
import { getContentAsString } from "../../extractor";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";
import { OsReleaseFilePath } from "../../types";

const getOsReleaseAction: ExtractAction = {
  actionName: "os-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.Linux),
  callback: streamToString,
};

const getFallbackOsReleaseAction: ExtractAction = {
  actionName: "os-release-fallback",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.LinuxFallback),
  callback: streamToString,
};

const getLsbReleaseAction: ExtractAction = {
  actionName: "lsb-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.Lsb),
  callback: streamToString,
};

const getDebianVersionAction: ExtractAction = {
  actionName: "debian-version",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.Debian),
  callback: streamToString,
};

const getAlpineReleaseAction: ExtractAction = {
  actionName: "alpine-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.Alpine),
  callback: streamToString,
};

const getRedHatReleaseAction: ExtractAction = {
  actionName: "redhat-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.RedHat),
  callback: streamToString,
};

const getCentosReleaseAction: ExtractAction = {
  actionName: "centos-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.Centos),
  callback: streamToString,
};

const getOracleReleaseAction: ExtractAction = {
  actionName: "oracle-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.Oracle),
  callback: streamToString,
};

const getAlmaLinuxReleaseAction: ExtractAction = {
  actionName: "almalinux-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.AlmaLinux),
  callback: streamToString,
};

const getRockyReleaseAction: ExtractAction = {
  actionName: "rocky-release",
  filePathMatches: (filePath) =>
    filePath === normalizePath(OsReleaseFilePath.Rocky),
  callback: streamToString,
};

const osReleaseActionMap = {
  [OsReleaseFilePath.Linux]: getOsReleaseAction,
  [OsReleaseFilePath.LinuxFallback]: getFallbackOsReleaseAction,
  [OsReleaseFilePath.Lsb]: getLsbReleaseAction,
  [OsReleaseFilePath.Debian]: getDebianVersionAction,
  [OsReleaseFilePath.Alpine]: getAlpineReleaseAction,
  [OsReleaseFilePath.RedHat]: getRedHatReleaseAction,
  [OsReleaseFilePath.Centos]: getCentosReleaseAction,
  [OsReleaseFilePath.Oracle]: getOracleReleaseAction,
  [OsReleaseFilePath.AlmaLinux]: getAlmaLinuxReleaseAction,
  [OsReleaseFilePath.Rocky]: getRockyReleaseAction,
};

export const getOsReleaseActions: ExtractAction[] = [
  getOsReleaseAction,
  getFallbackOsReleaseAction,
  getLsbReleaseAction,
  getDebianVersionAction,
  getAlpineReleaseAction,
  getRedHatReleaseAction,
  getCentosReleaseAction,
  getOracleReleaseAction,
  getAlmaLinuxReleaseAction,
  getRockyReleaseAction,
];

export function getOsRelease(
  extractedLayers: ExtractedLayers,
  releasePath: OsReleaseFilePath,
): string {
  const osRelease = getContentAsString(
    extractedLayers,
    osReleaseActionMap[releasePath],
  );
  return osRelease || "";
}
