import { normalize as normalizePath } from "path";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

export const getDpkgPackageFileContentAction: ExtractAction = {
  actionName: "dpkg",
  filePathMatches: (filePath) =>
    filePath.startsWith(normalizePath("/var/lib/dpkg/status.d/")),
  callback: streamToString, // TODO replace with a parser for apt data extractor
};

export function getAptFiles(extractedLayers: ExtractedLayers): string[] {
  const files: string[] = [];

  for (const fileName of Object.keys(extractedLayers)) {
    if (!("dpkg" in extractedLayers[fileName])) {
      continue;
    }
    // when the nodejs distroless image is build, the metadata is added to status.d
    // this causes us to wronfgully identify nodejs as deb package
    // https://github.com/GoogleContainerTools/distroless/blob/main/private/remote/node_archive.bzl#L29
    if (fileName === "/var/lib/dpkg/status.d/nodejs") {
      continue;
    }
    files.push(extractedLayers[fileName].dpkg.toString("utf8"));
  }

  return files;
}
