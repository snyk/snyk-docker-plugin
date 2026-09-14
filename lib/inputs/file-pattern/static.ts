import { Minimatch, MinimatchOptions } from "minimatch";
import * as path from "path";

import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";
import { ManifestFile } from "../../types";

/**
 * Return false if any exclusion pattern matches,
 * return true if any inclusion pattern matches
 */
function generatePathMatcher(
  globsInclude: string[],
  globsExclude: string[],
): (filePath: string) => boolean {
  const matchOptions: MinimatchOptions = {
    windowsPathsNoEscape: true,
    optimizationLevel: 0,
  };

  const excludeMatchers = globsExclude.map(
    (glob) => new Minimatch(glob, matchOptions),
  );
  const includeMatchers = globsInclude.map(
    (glob) => new Minimatch(glob, matchOptions),
  );

  return (filePath: string): boolean => {
    if (excludeMatchers.some((matcher) => matcher.match(filePath))) {
      return false;
    }

    return includeMatchers.some((matcher) => matcher.match(filePath));
  };
}

export function generateExtractAction(
  globsInclude: string[],
  globsExclude: string[],
): ExtractAction {
  return {
    actionName: "find-files-by-pattern",
    filePathMatches: generatePathMatcher(globsInclude, globsExclude),
    callback: (dataStream, streamSize) =>
      streamToString(dataStream, streamSize, "base64"),
  };
}

export function getMatchingFiles(
  extractedLayers: ExtractedLayers,
): ManifestFile[] {
  const manifestFiles: ManifestFile[] = [];

  for (const filePath of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[filePath])) {
      if (actionName !== "find-files-by-pattern") {
        continue;
      }

      if (typeof extractedLayers[filePath][actionName] !== "string") {
        throw new Error("expected a string");
      }

      manifestFiles.push({
        name: path.basename(filePath),
        path: path.dirname(filePath),
        contents: extractedLayers[filePath][actionName] as string,
      });
    }
  }

  return manifestFiles;
}
