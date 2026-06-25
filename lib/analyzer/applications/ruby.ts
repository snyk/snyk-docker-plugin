import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import { getErrorMessage } from "../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const debug = Debug("snyk");
const PACKAGE_MANAGER_TYPE = "rubygems";

interface RubyProjectFiles {
  lock: string;
  // The Gemfile is optional: an image may ship only a Gemfile.lock. When it is
  // present we use it to drop development/test gems; without it we fall back to
  // the lockfile's DEPENDENCIES section, which has no group information.
  manifest?: string;
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
  const projects = findRubyProjects(filePathToContent);

  for (const project of projects) {
    const manifestContent = project.manifest
      ? filePathToContent[project.manifest]
      : undefined;

    let depGraph: DepGraph | null;
    try {
      depGraph = await buildDepGraphFromGemfileLock(
        filePathToContent[project.lock],
        project.lock,
        manifestContent,
      );
    } catch (err) {
      // Skip a malformed project rather than failing the whole image scan.
      debug(
        `Failed to parse Ruby Gemfile.lock at ${
          project.lock
        }: ${getErrorMessage(err)}`,
      );
      continue;
    }
    if (!depGraph) {
      continue;
    }

    const testedFiles = project.manifest
      ? [path.basename(project.manifest), path.basename(project.lock)]
      : [path.basename(project.lock)];

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph,
    };
    const testedFilesFact: TestedFilesFact = {
      type: "testedFiles",
      data: testedFiles,
    };
    scanResults.push({
      facts: [depGraphFact, testedFilesFact],
      identity: {
        type: depGraph.pkgManager.name,
        targetFile: project.lock,
      },
    });
  }

  return scanResults;
}

async function buildDepGraphFromGemfileLock(
  content: string,
  lockFilePath: string,
  manifestContent?: string,
): Promise<DepGraph | null> {
  const parsedLock = parseGemfileLock(content);

  // The Gemfile lets us scope the graph to gems that ship in production, i.e.
  // excluding development/test groups. Without it we keep every direct gem the
  // lockfile resolved.
  let directDependencies = parsedLock.dependencies;
  if (manifestContent !== undefined) {
    const manifest = parseGemfileManifestDependencies(manifestContent);
    if (manifest.foundGemDeclarations) {
      directDependencies = Array.from(manifest.dependencies);
    }
  }

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

function parseDependencyName(line: string): string | null {
  const match = line.match(/^([^\s(!;]+)!?/);
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
  return groups.some((group) => !excludedGroups.has(group));
}

function addSpec(specs: Map<string, RubyGemSpec[]>, spec: RubyGemSpec): void {
  const key = spec.name.toLowerCase();
  if (!specs.has(key)) {
    specs.set(key, []);
  }
  specs.get(key)!.push(spec);
}

// We only build a graph for a Gemfile.lock; a Gemfile alone has no resolved
// versions. When both files share a directory we pair them so development/test
// gems can be filtered out.
function findRubyProjects(
  filePathToContent: FilePathToContent,
): RubyProjectFiles[] {
  const filesByDir = Object.keys(filePathToContent).reduce<
    Record<string, Set<string>>
  >((acc, filePath) => {
    const dir = path.dirname(filePath);
    (acc[dir] ??= new Set()).add(path.basename(filePath));
    return acc;
  }, {});

  const projects: RubyProjectFiles[] = [];
  for (const dir of Object.keys(filesByDir)) {
    const files = filesByDir[dir];
    if (!files.has("Gemfile.lock")) {
      continue;
    }
    projects.push({
      lock: path.join(dir, "Gemfile.lock"),
      manifest: files.has("Gemfile") ? path.join(dir, "Gemfile") : undefined,
    });
  }

  return projects;
}
