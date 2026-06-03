import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

/**
 * Matches *.deps.json files produced by `dotnet publish`.
 * Excludes framework deps.json files under the shared runtime directory
 * (e.g. /usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.0/).
 */
function filePathMatches(filePath: string): boolean {
  if (
    !filePath.endsWith(".deps.json") ||
    filePath.includes("/dotnet/shared/") ||
    filePath.includes("/dotnet/packs/")
  ) {
    return false;
  }
  return true;
}

export const getDotnetAppFileContentAction: ExtractAction = {
  actionName: "dotnet-app-files",
  filePathMatches,
  callback: streamToString,
};
