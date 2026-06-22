import * as Debug from "debug";
import { SymlinkMap } from "../../extractor/types";
import {
  AnalysisType,
  AnalyzedPackageWithVersion,
  ImageAnalysis,
  ImagePackagesAnalysis,
  OSRelease,
} from "../types";
import {
  canonicalizePath,
  normalizeAbsolutePath,
  SymlinkGraph,
} from "./path-canonicalization";

export interface ApkPackageOwnership {
  distroId: string;
  packageName: string;
  packageVersion: string;
  originPackage: string;
  evidencePaths: string[];
}

export type MatchKind = "exact" | "directory";

export interface PathOwnerMatch {
  owner: AnalyzedPackageWithVersion;
  matchKind: MatchKind;
  /** Number of matched path segments; a deeper directory match outranks a shallower one. */
  prefixLength: number;
}

interface DirectoryTrieNode {
  owners: AnalyzedPackageWithVersion[];
  children: Map<string, DirectoryTrieNode>;
}

export interface ApkPathIndex {
  exactFileOwners: Map<string, AnalyzedPackageWithVersion[]>;
  directoryTrie: DirectoryTrieNode;
}

const debug = Debug("snyk");

const CHAINGUARD_DISTROS = new Set(["wolfi", "chainguard"]);

export function isChainguardDistro(osRelease: OSRelease): boolean {
  return CHAINGUARD_DISTROS.has(osRelease.name);
}

export function toSymlinkGraph(symlinks?: SymlinkMap): SymlinkGraph {
  const graph: SymlinkGraph = new Map();
  if (!symlinks) {
    return graph;
  }
  for (const [symlinkPath, target] of Object.entries(symlinks)) {
    graph.set(normalizeAbsolutePath(symlinkPath), target);
  }
  return graph;
}

export function buildApkPathIndex(
  packages: AnalyzedPackageWithVersion[],
  symlinkGraph: SymlinkGraph,
): ApkPathIndex {
  const exactFileOwners = new Map<string, AnalyzedPackageWithVersion[]>();
  const directoryTrie: DirectoryTrieNode = { owners: [], children: new Map() };

  for (const pkg of packages) {
    for (const filePath of pkg.Files ?? []) {
      const canonical = canonicalizePath(filePath, symlinkGraph);
      addToOwnerMap(exactFileOwners, canonical, pkg);
    }

    for (const dirPath of pkg.Directories ?? []) {
      const canonical = canonicalizePath(dirPath, symlinkGraph);
      insertDirectoryOwner(directoryTrie, canonical, pkg);
    }
  }

  return { exactFileOwners, directoryTrie };
}

export function resolveOwnerForEvidencePath(
  evidencePath: string,
  index: ApkPathIndex,
  symlinkGraph: SymlinkGraph,
): PathOwnerMatch | undefined {
  const canonical = canonicalizePath(evidencePath, symlinkGraph);
  const exactOwners = index.exactFileOwners.get(canonical);
  if (exactOwners && exactOwners.length > 0) {
    return {
      owner: pickExactOwner(exactOwners),
      matchKind: "exact",
      prefixLength: canonical.split("/").filter(Boolean).length,
    };
  }

  return resolveDirectoryOwner(canonical, index);
}

function resolveDirectoryOwner(
  canonicalPath: string,
  index: ApkPathIndex,
): PathOwnerMatch | undefined {
  const segments = canonicalPath.split("/").filter(Boolean);
  let node = index.directoryTrie;
  let best: PathOwnerMatch | undefined;

  for (let i = 0; i < segments.length; i++) {
    const child = node.children.get(segments[i]);
    if (!child) {
      break;
    }
    node = child;
    if (node.owners.length > 0) {
      best = {
        owner: pickExactOwner(node.owners),
        matchKind: "directory",
        prefixLength: i + 1,
      };
    }
  }

  return best;
}

/**
 * Resolve APK package ownership for app evidence paths on Wolfi/Chainguard images.
 *
 * Per Chainguard's scanner spec, an app dependency is owned by an APK package
 * only when its evidence paths are wholly contained in that package's declared
 * paths; a dependency with any unowned path is not covered by Chainguard's
 * advisory data and must keep its findings. This fact drives downstream
 * suppression, so we skip it rather than guess and risk suppressing real
 * vulnerabilities in user-added software.
 * https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/scanning_implementation.md
 */
export function resolveApkOwnership(
  evidencePaths: string[],
  packages: AnalyzedPackageWithVersion[],
  osRelease: OSRelease,
  symlinkGraph: SymlinkGraph,
): ApkPackageOwnership | undefined {
  if (!isChainguardDistro(osRelease) || evidencePaths.length === 0) {
    return undefined;
  }

  const index = buildApkPathIndex(packages, symlinkGraph);
  const perPathMatches: PathOwnerMatch[] = [];

  for (const evidencePath of evidencePaths) {
    const normalized = normalizeAbsolutePath(evidencePath);
    const match = resolveOwnerForEvidencePath(normalized, index, symlinkGraph);
    if (!match) {
      debug(
        `apk ownership skipped: no owning package for evidence path ${normalized}`,
      );
      return undefined;
    }
    perPathMatches.push(match);
  }

  const owner = pickConsistentOwner(perPathMatches);
  if (!owner) {
    return undefined;
  }

  return {
    distroId: osRelease.name,
    packageName: owner.Name,
    packageVersion: owner.Version,
    originPackage: owner.Source ?? owner.Name,
    evidencePaths,
  };
}

function ownerKey(pkg: AnalyzedPackageWithVersion): string {
  return `${pkg.Name}@${pkg.Version}`;
}

function pickConsistentOwner(
  matches: PathOwnerMatch[],
): AnalyzedPackageWithVersion | undefined {
  return uniqueOwner(matches) ?? pickBestOwnerAcrossPaths(matches);
}

/**
 * When evidence paths disagree on an owner, an owner backed by an exact file
 * match outranks owners only inferred from a parent directory; among
 * directory-only matches, the deepest prefix wins. Evidence that is still
 * split between owners yields no owner.
 */
function pickBestOwnerAcrossPaths(
  matches: PathOwnerMatch[],
): AnalyzedPackageWithVersion | undefined {
  const exactMatches = matches.filter((m) => m.matchKind === "exact");
  if (exactMatches.length > 0) {
    return uniqueOwner(exactMatches);
  }

  const deepest = Math.max(...matches.map((m) => m.prefixLength));
  return uniqueOwner(matches.filter((m) => m.prefixLength === deepest));
}

function uniqueOwner(
  matches: PathOwnerMatch[],
): AnalyzedPackageWithVersion | undefined {
  const first = matches[0].owner;
  return matches.every((m) => ownerKey(m.owner) === ownerKey(first))
    ? first
    : undefined;
}

function pickExactOwner(
  owners: AnalyzedPackageWithVersion[],
): AnalyzedPackageWithVersion {
  if (owners.length === 1) {
    return owners[0];
  }
  const originMatch = owners.find((o) => o.Name === o.Source);
  return originMatch ?? owners[0];
}

function addToOwnerMap(
  map: Map<string, AnalyzedPackageWithVersion[]>,
  canonicalPath: string,
  pkg: AnalyzedPackageWithVersion,
): void {
  const existing = map.get(canonicalPath) ?? [];
  existing.push(pkg);
  map.set(canonicalPath, existing);
}

function insertDirectoryOwner(
  root: DirectoryTrieNode,
  dirPath: string,
  pkg: AnalyzedPackageWithVersion,
): void {
  const segments = dirPath.split("/").filter(Boolean);
  let node = root;
  for (const segment of segments) {
    let child = node.children.get(segment);
    if (!child) {
      child = { owners: [], children: new Map() };
      node.children.set(segment, child);
    }
    node = child;
  }
  node.owners.push(pkg);
}

export function getApkPackagesFromResults(
  results?: ImageAnalysis[],
): AnalyzedPackageWithVersion[] {
  if (!results) {
    return [];
  }
  const apkResult = results.find((r) => r.AnalyzeType === AnalysisType.Apk) as
    | ImagePackagesAnalysis
    | undefined;
  return apkResult?.Analysis ?? [];
}
