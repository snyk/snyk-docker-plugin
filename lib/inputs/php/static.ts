import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const phpAppFiles = ["composer.json", "composer.lock"];
const deletedAppFiles = phpAppFiles.map((file) => ".wh." + file);
// Match both forward slashes (POSIX/macOS/Linux) and backslashes (Windows);
// anchored on the vendor/composer/ path segment so an unrelated installed.json
// elsewhere on the image is not swept in. Also matches the whiteout form so
// deletions of a previously-extracted installed.json are recorded.
const vendorComposerInstalledJsonRegex =
  /[\/\\]vendor[\/\\]composer[\/\\](?:\.wh\.)?installed\.json$/;

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return (
    phpAppFiles.includes(fileName) ||
    deletedAppFiles.includes(fileName) ||
    vendorComposerInstalledJsonRegex.test(filePath)
  );
}

export const getPhpAppFileContentAction: ExtractAction = {
  actionName: "php-app-files",
  filePathMatches,
  callback: streamToString,
};
