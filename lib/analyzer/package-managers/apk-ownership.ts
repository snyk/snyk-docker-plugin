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
      prefixLength: canonical.length,
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
        owner: pickDirectoryOwner(node.owners),
        matchKind: "directory",
        prefixLength: i + 1,
      };
    }
  }

  if (!best && node.owners.length > 0) {
    best = {
      owner: pickDirectoryOwner(node.owners),
      matchKind: "directory",
      prefixLength: segments.length,
    };
  }

  return best;
}

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

function pickConsistentOwner(
  matches: PathOwnerMatch[],
): AnalyzedPackageWithVersion | undefined {
  const ownerKey = (pkg: AnalyzedPackageWithVersion) =>
    `${pkg.Name}@${pkg.Version}`;

  const firstKey = ownerKey(matches[0].owner);
  const allSame = matches.every((m) => ownerKey(m.owner) === firstKey);
  if (allSame) {
    return matches[0].owner;
  }

  return pickBestOwnerAcrossPaths(matches);
}

function pickBestOwnerAcrossPaths(
  matches: PathOwnerMatch[],
): AnalyzedPackageWithVersion | undefined {
  const scores = new Map<
    string,
    { pkg: AnalyzedPackageWithVersion; score: number }
  >();

  for (const match of matches) {
    const key = `${match.owner.Name}@${match.owner.Version}`;
    const exactBonus = match.matchKind === "exact" ? 1000 : 0;
    const score = exactBonus + match.prefixLength;
    const existing = scores.get(key);
    if (!existing || score > existing.score) {
      scores.set(key, { pkg: match.owner, score });
    }
  }

  const entries = [...scores.values()];
  if (entries.length === 0) {
    return undefined;
  }

  entries.sort((a, b) => b.score - a.score);
  const topScore = entries[0].score;
  const topEntries = entries.filter((e) => e.score === topScore);
  if (topEntries.length === 1) {
    return topEntries[0].pkg;
  }

  return undefined;
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

function pickDirectoryOwner(
  owners: AnalyzedPackageWithVersion[],
): AnalyzedPackageWithVersion {
  return pickExactOwner(owners);
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
