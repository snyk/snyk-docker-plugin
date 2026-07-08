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

export interface OwnedPackage {
  // The file(s)/dir(s) that justify this ownership. Always present — the
  // universal key across ecosystems (jar files, npm install dirs, Go binaries).
  evidencePaths: string[];
  // The apk package that owns the evidence paths.
  apkPackageName: string;
  apkPackageVersion: string;
  // apk Source package (falls back to apkPackageName).
  originPackage: string;
  // Dependency coordinate (name@version) for per-package ecosystems where only
  // some of a result's dependencies are owned — npm global modules. Absent for
  // whole-result entries (Go binaries, Java jar dirs), where the entire result
  // is owned and downstream relabels every dependency it produced.
  name?: string;
  version?: string;
}

export interface ApkPackageOwnership {
  distroId: string;
  ownedPackages: OwnedPackage[];
}

// A unit of evidence to resolve ownership for. Each candidate is resolved
// independently (fail closed per candidate): all of its evidence paths must
// resolve to one consistent apk package, or it is omitted.
export interface OwnershipCandidate {
  evidencePaths: string[];
  name?: string;
  version?: string;
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

const CHAINGUARD_DISTROS = new Set(["wolfi", "chainguard"]);

export function isChainguardDistro(osRelease?: OSRelease): boolean {
  return !!osRelease && CHAINGUARD_DISTROS.has(osRelease.name.toLowerCase());
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
  let deepestOwners: AnalyzedPackageWithVersion[] | undefined;
  let deepestPrefix = 0;

  for (let i = 0; i < segments.length; i++) {
    const child = node.children.get(segments[i]);
    if (!child) {
      break;
    }
    node = child;
    if (node.owners.length > 0) {
      deepestOwners = node.owners;
      deepestPrefix = i + 1;
    }
  }

  if (!deepestOwners) {
    return undefined;
  }

  // A directory declared by more than one distinct package is shared, so no
  // single package wholly owns its contents. Fail closed rather than guess.
  const owner = uniqueDeclaredOwner(deepestOwners);
  if (!owner) {
    return undefined;
  }

  return { owner, matchKind: "directory", prefixLength: deepestPrefix };
}

function uniqueDeclaredOwner(
  owners: AnalyzedPackageWithVersion[],
): AnalyzedPackageWithVersion | undefined {
  const first = owners[0];
  return owners.every((o) => ownerKey(o) === ownerKey(first))
    ? first
    : undefined;
}

/**
 * Resolve APK package ownership for a set of candidates on Wolfi/Chainguard
 * images. Each candidate (a single npm package, or a whole Go/Java result) is
 * resolved independently: all of its evidence paths must be wholly owned by one
 * consistent APK package, or the candidate is omitted (fail closed per
 * candidate). Per Chainguard's scanner spec, a dependency with any unowned path
 * is not covered by advisory data and must keep its findings — we skip rather
 * than guess and risk suppressing real vulnerabilities in user-added software.
 * Candidates carrying a coordinate (name@version) are deduplicated, keeping an
 * owned occurrence over an unowned one.
 * https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/scanning_implementation.md
 */
export function resolveApkOwnership(
  candidates: OwnershipCandidate[],
  index: ApkPathIndex,
  symlinkGraph: SymlinkGraph,
  osRelease: OSRelease,
): ApkPackageOwnership | undefined {
  if (!isChainguardDistro(osRelease) || candidates.length === 0) {
    return undefined;
  }

  const ownedPackages: OwnedPackage[] = [];
  // `seen` holds matched coordinates only, so an owned occurrence always wins
  // over an unowned one. It must NOT include unmatched coordinates, or a later
  // owned copy of the same coordinate would be skipped.
  const seen = new Set<string>();
  // Memoize per-path owner lookups so a path shared by several candidates (or an
  // unmatched coordinate seen repeatedly) is resolved only once.
  const resolvedByPath = new Map<
    string,
    ReturnType<typeof resolveOwnerForEvidencePath>
  >();
  // Sort by first evidence path so coordinate dedup is deterministic regardless
  // of discovery order: when a coordinate is bundled under more than one apk
  // package, the lexicographically-first evidence path wins. Which origin is
  // "correct" in that case is a downstream (@snyk/vuln) question.
  const ordered = [...candidates].sort((a, b) =>
    (a.evidencePaths[0] ?? "").localeCompare(b.evidencePaths[0] ?? ""),
  );

  for (const candidate of ordered) {
    if (candidate.evidencePaths.length === 0) {
      continue;
    }
    const coordinate =
      candidate.name && candidate.version
        ? `${candidate.name}@${candidate.version}`
        : undefined;
    if (coordinate && seen.has(coordinate)) {
      continue;
    }

    // Fail closed per candidate: every evidence path must resolve to one
    // consistent owner, else the candidate keeps its findings.
    const matches: PathOwnerMatch[] = [];
    let allOwned = true;
    for (const evidencePath of candidate.evidencePaths) {
      const normalized = normalizeAbsolutePath(evidencePath);
      if (!resolvedByPath.has(normalized)) {
        resolvedByPath.set(
          normalized,
          resolveOwnerForEvidencePath(normalized, index, symlinkGraph),
        );
      }
      const match = resolvedByPath.get(normalized);
      if (!match) {
        allOwned = false;
        break;
      }
      matches.push(match);
    }
    if (!allOwned) {
      continue;
    }

    const owner = pickConsistentOwner(matches);
    if (!owner) {
      continue;
    }

    if (coordinate) {
      seen.add(coordinate);
    }
    ownedPackages.push({
      evidencePaths: candidate.evidencePaths,
      apkPackageName: owner.Name,
      apkPackageVersion: owner.Version,
      originPackage: owner.Source ?? owner.Name,
      ...(candidate.name ? { name: candidate.name } : {}),
      ...(candidate.version ? { version: candidate.version } : {}),
    });
  }

  if (ownedPackages.length === 0) {
    return undefined;
  }

  return { distroId: osRelease.name, ownedPackages };
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
