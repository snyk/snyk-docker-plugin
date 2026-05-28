/**
 * check if a file is 'whited out' (filename starts with .wh.)
 * https://www.madebymikal.com/interpreting-whiteout-files-in-docker-image-layers
 * https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts
 */
export function isWhitedOutFile(filename: string): boolean {
  return getBasename(filename).startsWith(".wh.");
}

/**
 * Check if a file is an opaque whiteout (.wh..wh..opq).
 * Opaque whiteouts mean "delete everything in this directory from lower layers."
 * https://github.com/opencontainers/image-spec/blob/main/layer.md#opaque-whiteout
 */
export function isOpaqueWhiteout(filename: string): boolean {
  return getBasename(filename) === ".wh..wh..opq";
}

/**
 * Remove the .wh. prefix from a whiteout file to get the original filename
 */
export function removeWhiteoutPrefix(filename: string): string {
  // Replace .wh. at the start or after the last slash/backslash.
  // Don't match if there are slashes after .wh.
  return filename.replace(/^(.*[\/\\])?\.wh\.([^\/\\]*)$/, "$1$2");
}

/**
 * Extract the basename from a path, handling both / and \ separators cross-platform.
 */
function getBasename(filename: string): string {
  const lastSlash = Math.max(
    filename.lastIndexOf("/"),
    filename.lastIndexOf("\\"),
  );
  return lastSlash === -1 ? filename : filename.substring(lastSlash + 1);
}
