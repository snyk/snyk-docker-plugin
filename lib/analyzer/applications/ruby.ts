import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import { getErrorMessage } from "../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

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
  specs: Map<string, RubyGemSpec>;
  dependencies: string[];
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
): Promise<DepGraph | null> {
  const parsedLock = parseGemfileLock(content);
  if (parsedLock.specs.size === 0 || parsedLock.dependencies.length === 0) {
    return null;
  }

  const builder = new DepGraphBuilder(
    { name: PACKAGE_MANAGER_TYPE },
    { name: lockFilePath },
  );
  const visited = new Set<string>();

  for (const dependency of parsedLock.dependencies) {
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
  specs: Map<string, RubyGemSpec>,
  visited: Set<string>,
  builder: DepGraphBuilder,
): Promise<void> {
  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  const spec = specs.get(dependencyName.toLowerCase());
  if (!spec) {
    return;
  }

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
  const specs = new Map<string, RubyGemSpec>();
  const dependencies: string[] = [];
  const lines = content.split(/\r?\n/);

  let currentSection: string | null = null;
  let inSpecsBlock = false;
  let currentSpec: RubyGemSpec | null = null;

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) {
      continue;
    }

    if (isSectionHeader(line)) {
      currentSection = trimmedLine;
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

    if (currentSection === "DEPENDENCIES") {
      const dependency = parseDependencyName(trimmedLine);
      if (dependency && !dependencies.includes(dependency)) {
        dependencies.push(dependency);
      }
    }
  }

  return { specs, dependencies };
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

function addSpec(specs: Map<string, RubyGemSpec>, spec: RubyGemSpec): void {
  const key = spec.name.toLowerCase();
  if (!specs.has(key)) {
    specs.set(key, spec);
  }
}

function findManifestLockPairsInSameDirectory(
  filePathToContent: FilePathToContent,
): ManifestLockPathPair[] {
  const fileNamesGroupedByDirectory = groupFilesByDirectory(filePathToContent);
  const manifestLockPathPairs: ManifestLockPathPair[] = [];

  for (const directoryPath of Object.keys(fileNamesGroupedByDirectory)) {
    const filesInDirectory = fileNamesGroupedByDirectory[directoryPath];
    const hasGemfile = filesInDirectory.includes("Gemfile");
    const hasGemfileLock = filesInDirectory.includes("Gemfile.lock");

    if (hasGemfile && hasGemfileLock) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "Gemfile"),
        lock: path.join(directoryPath, "Gemfile.lock"),
      });
    }
  }

  return manifestLockPathPairs;
}

function groupFilesByDirectory(filePathToContent: FilePathToContent): {
  [directoryName: string]: string[];
} {
  const fileNamesGroupedByDirectory: { [directoryName: string]: string[] } = {};
  for (const filePath of Object.keys(filePathToContent)) {
    const directory = path.dirname(filePath);
    const fileName = path.basename(filePath);
    if (!fileNamesGroupedByDirectory[directory]) {
      fileNamesGroupedByDirectory[directory] = [];
    }
    fileNamesGroupedByDirectory[directory].push(fileName);
  }
  return fileNamesGroupedByDirectory;
}
