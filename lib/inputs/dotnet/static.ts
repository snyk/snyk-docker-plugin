import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const DOTNET_EXCLUSIONS = [
  "/dotnet/shared/",
  "/dotnet/packs/",
  "/dotnet/sdk/",
  "/.nuget/packages/",
];

function isExcluded(normalizedPath: string): boolean {
  return DOTNET_EXCLUSIONS.some((segment) => normalizedPath.includes(segment));
}

function matchesProjectAssetsJson(normalizedPath: string): boolean {
  if (!normalizedPath.endsWith("project.assets.json")) {
    return false;
  }
  return normalizedPath.includes("/obj/");
}

/**
 * Matches NuGet manifest and lockfile formats used by application projects:
 * *.deps.json (publish output), packages.config, *.csproj/*.fsproj/*.vbproj,
 * packages.lock.json, and obj/project.assets.json (restore output).
 *
 * Excludes framework/runtime files under the shared dotnet install and NuGet
 * cache paths (shared, packs, sdk, and restored package contentFiles).
 */
function filePathMatches(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");

  if (isExcluded(normalizedPath)) {
    return false;
  }

  if (normalizedPath.endsWith(".deps.json")) {
    return true;
  }

  if (normalizedPath.endsWith("packages.config")) {
    return true;
  }

  if (
    normalizedPath.endsWith(".csproj") ||
    normalizedPath.endsWith(".fsproj") ||
    normalizedPath.endsWith(".vbproj")
  ) {
    return true;
  }

  if (normalizedPath.endsWith("packages.lock.json")) {
    return true;
  }

  if (matchesProjectAssetsJson(normalizedPath)) {
    return true;
  }

  return false;
}

export const getDotnetAppFileContentAction: ExtractAction = {
  actionName: "dotnet-app-files",
  filePathMatches,
  callback: streamToString,
};
