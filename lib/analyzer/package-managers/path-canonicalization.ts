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
  const normalized = normalizeAbsolutePath(filePath);
  const segments = normalized.split("/").filter(Boolean);
  const resolvedSegments: string[] = [];

  for (const segment of segments) {
    resolvedSegments.push(segment);
    const currentPath = `/${resolvedSegments.join("/")}`;
    const linkTarget = symlinkGraph.get(currentPath);
    if (!linkTarget) {
      continue;
    }

    const resolvedTarget = resolveSymlinkChain(
      normalizeSymlinkTarget(currentPath, linkTarget),
      symlinkGraph,
    );
    const targetSegments = resolvedTarget.split("/").filter(Boolean);
    resolvedSegments.length = 0;
    resolvedSegments.push(...targetSegments);
  }

  return resolvedSegments.length === 0 ? "/" : `/${resolvedSegments.join("/")}`;
}

function normalizeSymlinkTarget(basePath: string, linkTarget: string): string {
  const target = linkTarget.replace(/\\/g, "/");
  if (target.startsWith("/")) {
    return path.normalize(target);
  }
  const baseDir = path.dirname(basePath);
  return path.normalize(path.join(baseDir, target));
}

function resolveSymlinkChain(
  filePath: string,
  symlinkGraph: SymlinkGraph,
): string {
  let current = normalizeAbsolutePath(filePath);
  const visited = new Set<string>();

  for (let depth = 0; depth < MAX_SYMLINK_DEPTH; depth++) {
    const linkTarget = symlinkGraph.get(current);
    if (!linkTarget) {
      return current;
    }
    if (visited.has(current)) {
      return current;
    }
    visited.add(current);
    current = normalizeSymlinkTarget(current, linkTarget);
  }

  return current;
}
