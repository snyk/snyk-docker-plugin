import { posix as path } from "path";

export type SymlinkGraph = Map<string, string>;

const MAX_SYMLINK_DEPTH = 40;

/**
 * Normalize a filesystem path to a POSIX absolute path without resolving symlinks.
 */
export function normalizeAbsolutePath(filePath: string): string {
  const normalized = path.normalize(filePath.replace(/\\/g, "/"));
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

/**
 * Resolve symlinks in a path using the extracted image symlink graph.
 * Used so evidence paths like /bin/node match APK file lists recorded at /usr/bin/node.
 */
export function canonicalizePath(
  filePath: string,
  symlinkGraph: SymlinkGraph,
): string {
  let current = normalizeAbsolutePath(filePath);
  const visited = new Set<string>();

  // Re-scan from the start after each substitution so that a resolved target
  // whose own parent is a symlink (e.g. /lib64 -> /lib/x with /lib -> /usr/lib)
  // is fully resolved. MAX_SYMLINK_DEPTH and the visited set guard against cycles.
  for (let depth = 0; depth < MAX_SYMLINK_DEPTH; depth++) {
    if (visited.has(current)) {
      return current;
    }
    visited.add(current);

    const segments = current.split("/").filter(Boolean);
    const prefix: string[] = [];
    let rewritten = false;

    for (const segment of segments) {
      prefix.push(segment);
      const linkTarget = symlinkGraph.get(`/${prefix.join("/")}`);
      if (!linkTarget) {
        continue;
      }
      const resolvedPrefix = normalizeSymlinkTarget(
        `/${prefix.join("/")}`,
        linkTarget,
      );
      const rest = segments.slice(prefix.length).join("/");
      current = normalizeAbsolutePath(
        rest ? `${resolvedPrefix}/${rest}` : resolvedPrefix,
      );
      rewritten = true;
      break;
    }

    if (!rewritten) {
      return current;
    }
  }

  return current;
}

function normalizeSymlinkTarget(basePath: string, linkTarget: string): string {
  const target = linkTarget.replace(/\\/g, "/");
  if (target.startsWith("/")) {
    return path.normalize(target);
  }
  const baseDir = path.dirname(basePath);
  return path.normalize(path.join(baseDir, target));
}
