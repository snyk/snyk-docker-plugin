import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import { getErrorMessage } from "../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

// Builds rubygems dep-graphs from Bundler files found in a container image.
// Gemfile.lock is the source of truth for the resolved tree (every gem and its
// pinned version + edges). The Gemfile manifest is consulted only to decide
// which top-level gems are graph roots and to drop development/test-only gems,
// which the lockfile alone cannot distinguish.
const debug = Debug("snyk");
const PACKAGE_MANAGER_TYPE = "rubygems";

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
}

interface RubyGemSpec {
  name: string;
  version: string;
  dependencies: string[];
}

interface ParsedGemfileLock {
  specs: Map<string, RubyGemSpec[]>;
  dependencies: string[];
}

interface ParsedGemfileManifest {
  dependencies: Set<string>;
  foundGemDeclarations: boolean;
}

export async function rubyFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  const filePairs = findManifestLockPairsInSameDirectory(filePathToContent);

  for (const pathPair of filePairs) {
    let depGraph: DepGraph | null;
    try {
      depGraph = await buildDepGraphFromGemfileLock(
        filePathToContent[pathPair.lock],
        pathPair.lock,
        filePathToContent[pathPair.manifest],
      );
    } catch (err) {
      debug(
        `Failed to parse Ruby Gemfile.lock at ${
          pathPair.lock
        }: ${getErrorMessage(err)}`,
      );
      continue;
    }
    if (!depGraph) {
      continue;
    }

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph,
    };
    const testedFilesFact: TestedFilesFact = {
      type: "testedFiles",
      data: [path.basename(pathPair.manifest), path.basename(pathPair.lock)],
    };
    scanResults.push({
      facts: [depGraphFact, testedFilesFact],
      identity: {
        type: depGraph.pkgManager.name,
        targetFile: pathPair.lock,
      },
    });
  }

  return scanResults;
}

async function buildDepGraphFromGemfileLock(
  content: string,
  lockFilePath: string,
  manifestContent: string,
): Promise<DepGraph | null> {
  const parsedLock = parseGemfileLock(content);
  const manifest = parseGemfileManifestDependencies(manifestContent);
  // Prefer the manifest's gem list (it carries group info, so dev/test gems are
  // already filtered out). Fall back to the lockfile's DEPENDENCIES section when
  // the Gemfile is missing or has no parseable `gem` lines.
  const directDependencies = manifest.foundGemDeclarations
    ? Array.from(manifest.dependencies)
    : parsedLock.dependencies;

  if (parsedLock.specs.size === 0 || directDependencies.length === 0) {
    return null;
  }

  const builder = new DepGraphBuilder(
    { name: PACKAGE_MANAGER_TYPE },
    { name: lockFilePath },
  );
  const visited = new Set<string>();

  for (const dependency of directDependencies) {
    await addDependencyToDepGraph(
      builder.rootNodeId,
      dependency,
      parsedLock.specs,
      visited,
      builder,
    );
  }

  const depGraph = builder.build();
  if (depGraph.getDepPkgs().length === 0) {
    return null;
  }

  return depGraph;
}

async function addDependencyToDepGraph(
  parentNodeId: string,
  dependencyName: string,
  specs: Map<string, RubyGemSpec[]>,
  visited: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  // A single gem name can resolve to several locked specs (one per platform,
  // e.g. nokogiri pure-ruby + nokogiri-aarch64-linux-gnu). We connect every
  // variant — this mirrors the lockfile's own multi-platform resolution.
  const matchingSpecs = specs.get(dependencyName.toLowerCase());
  if (!matchingSpecs) {
    return;
  }

  for (const spec of matchingSpecs) {
    await addSpecToDepGraph(parentNodeId, spec, specs, visited, builder);
  }
}

async function addSpecToDepGraph(
  parentNodeId: string,
  spec: RubyGemSpec,
  specs: Map<string, RubyGemSpec[]>,
  visited: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  // Create each pkg node (and recurse into its children) exactly once, but
  // always connect the parent->child edge — the same gem can be depended on by
  // multiple parents even though we only want to walk its subtree once.
  const nodeId = `${spec.name}@${spec.version}`;
  if (!visited.has(nodeId)) {
    visited.add(nodeId);
    builder.addPkgNode({ name: spec.name, version: spec.version }, nodeId);

    for (const childName of spec.dependencies) {
      await addDependencyToDepGraph(nodeId, childName, specs, visited, builder);
    }
  }
  builder.connectDep(parentNodeId, nodeId);
}

// Parses the relevant slices of a Gemfile.lock. The format is indentation-based:
//
//   GEM
//     specs:
//       rails (7.0.8)          <- 4-space indent: a resolved spec (name + version)
//         actionpack (= 7.0.8) <- 6-space indent: that spec's dependency
//   DEPENDENCIES
//     rails                    <- the gems declared directly in the Gemfile
//
// We collect every spec (keyed lowercase, since a gem may have multiple platform
// variants) and the DEPENDENCIES list (used as roots only when the Gemfile is
// unavailable).
function parseGemfileLock(content: string): ParsedGemfileLock {
  const specs = new Map<string, RubyGemSpec[]>();
  const dependencies = new Set<string>();
  const lines = content.split(/\r?\n/);

  let inDependencies = false;
  let inSpecsBlock = false;
  let currentSpec: RubyGemSpec | null = null;

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) {
      continue;
    }

    if (isSectionHeader(line)) {
      inDependencies = trimmedLine === "DEPENDENCIES";
      inSpecsBlock = false;
      currentSpec = null;
      continue;
    }

    if (trimmedLine === "specs:") {
      inSpecsBlock = true;
      currentSpec = null;
      continue;
    }

    if (inSpecsBlock) {
      const spec = parseSpecLine(line);
      if (spec) {
        currentSpec = spec;
        addSpec(specs, spec);
        continue;
      }

      const dependency = parseSpecDependencyLine(line);
      if (dependency && currentSpec) {
        currentSpec.dependencies.push(dependency);
      }
      continue;
    }

    if (inDependencies) {
      const dependency = parseDependencyName(trimmedLine);
      if (dependency) {
        dependencies.add(dependency);
      }
    }
  }

  return { specs, dependencies: [...dependencies] };
}

// Extracts the gem names declared in a Gemfile, excluding any that live only in
// development/test groups. Groups can be set two ways: a `group :x do ... end`
// block, or an inline `gem "x", group: :y` option. blockStack tracks the
// enclosing `do`/`end` blocks so we know which group(s) a gem sits inside;
// non-group blocks (e.g. `source ... do`) are pushed too so `end` lines stay
// balanced.
function parseGemfileManifestDependencies(
  content: string,
): ParsedGemfileManifest {
  const dependencies = new Set<string>();
  let foundGemDeclarations = false;
  const blockStack: Array<{ type: "group" | "other"; groups: string[] }> = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = stripTrailingComment(rawLine);
    const trimmedLine = line.trim();
    if (!trimmedLine) {
      continue;
    }

    const groupBlock = trimmedLine.match(/^group\s+(.+?)\s+do\b/);
    if (groupBlock) {
      blockStack.push({
        type: "group",
        groups: parseRubySymbols(groupBlock[1]),
      });
      continue;
    }

    if (trimmedLine === "end") {
      blockStack.pop();
      continue;
    }

    const gemName = parseGemName(trimmedLine);
    if (gemName) {
      foundGemDeclarations = true;
      const groups = [
        ...blockStack
          .filter((block) => block.type === "group")
          .flatMap((block) => block.groups),
        ...parseInlineGemGroups(trimmedLine),
      ];
      if (shouldIncludeGemGroup(groups)) {
        dependencies.add(gemName);
      }
      continue;
    }

    if (/\bdo\b/.test(trimmedLine)) {
      blockStack.push({ type: "other", groups: [] });
    }
  }

  return { dependencies, foundGemDeclarations };
}

function isSectionHeader(line: string): boolean {
  return /^[A-Z][A-Z0-9 _-]*$/.test(line);
}

function parseSpecLine(line: string): RubyGemSpec | null {
  const match = line.match(/^ {4}([^\s(]+) \(([^)]+)\)$/);
  if (!match) {
    return null;
  }

  return {
    name: match[1],
    version: match[2],
    dependencies: [],
  };
}

function parseSpecDependencyLine(line: string): string | null {
  if (!line.startsWith("      ")) {
    return null;
  }
  return parseDependencyName(line.trim());
}

// Pulls the gem name off a dependency line, stopping at whitespace, a version
// constraint `(`, a `!` (marks a path/git-pinned gem in DEPENDENCIES), or `;`.
function parseDependencyName(line: string): string | null {
  const match = line.match(/^([^\s(!;]+)/);
  return match ? match[1] : null;
}

function stripTrailingComment(line: string): string {
  return line.replace(/\s+#.*$/, "");
}

function parseGemName(line: string): string | null {
  const match = line.match(/^gem\s+["']([^"']+)["']/);
  return match ? match[1] : null;
}

function parseInlineGemGroups(line: string): string[] {
  const groups: string[] = [];
  const groupMatches = line.matchAll(/(?:group|groups):\s*(\[[^\]]+\]|:\w+)/g);
  for (const match of groupMatches) {
    groups.push(...parseRubySymbols(match[1]));
  }
  return groups;
}

function parseRubySymbols(value: string): string[] {
  return [...value.matchAll(/:(\w+)/g)].map((match) => match[1]);
}

function shouldIncludeGemGroup(groups: string[]): boolean {
  if (groups.length === 0) {
    return true;
  }
  const excludedGroups = new Set(["development", "test"]);
  // Include if ANY group is not excluded — a gem shared between e.g. :production
  // and :development must be kept, so this is `some`, not `every`.
  return groups.some((group) => !excludedGroups.has(group));
}

function addSpec(specs: Map<string, RubyGemSpec[]>, spec: RubyGemSpec): void {
  const key = spec.name.toLowerCase();
  if (!specs.has(key)) {
    specs.set(key, []);
  }
  specs.get(key)!.push(spec);
}

function findManifestLockPairsInSameDirectory(
  filePathToContent: FilePathToContent,
): ManifestLockPathPair[] {
  const byDir = Object.keys(filePathToContent).reduce<Record<string, string[]>>(
    (acc, filePath) => {
      const dir = path.dirname(filePath);
      (acc[dir] ??= []).push(path.basename(filePath));
      return acc;
    },
    {},
  );

  return Object.keys(byDir)
    .filter(
      (dir) =>
        byDir[dir].includes("Gemfile") && byDir[dir].includes("Gemfile.lock"),
    )
    .map((dir) => ({
      manifest: path.join(dir, "Gemfile"),
      lock: path.join(dir, "Gemfile.lock"),
    }));
}
