import { legacy } from "@snyk/dep-graph";
import * as gemfile from "@snyk/gemfile";
import * as path from "path";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { DepTreeDep } from "../../types";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const PACKAGE_MANAGER_TYPE = "rubygems";

/**
 * Lockfiles that are not application lockfiles:
 * - Ruby gem home: .../ruby/gems/<ruby-ver>/gems/<name>-<ver>/Gemfile.lock
 * - Bundler path:  .../bundle/gems/<name>-<ver>/Gemfile.lock
 * - Git checkouts: .../bundler/gems/<name>-<sha>/Gemfile.lock
 *
 * App lockfiles such as /app/Gemfile.lock, /usr/local/bundle/Gemfile.lock,
 * or /srv/gems/myapp-2/Gemfile.lock must not match.
 */
const INSTALLED_GEM_LOCKFILE =
  /(^|\/)(?:ruby\/gems\/[^/]+\/gems\/[^/]+-[0-9][^/]*|bundle\/gems\/[^/]+-[0-9][^/]*|bundler\/gems\/[^/]+)\/Gemfile\.lock$/;

export function isInstalledGemLockfile(filePath: string): boolean {
  // Normalize so Windows-style separators still match the layout rule.
  return INSTALLED_GEM_LOCKFILE.test(filePath.replace(/\\/g, "/"));
}

interface GemfileLockPath {
  lock: string;
  manifest?: string;
}

interface Gemspec {
  version?: string;
  [key: string]: unknown;
}

interface LockFileMeta {
  dependencies?: { [name: string]: unknown };
  specs?: { [name: string]: Gemspec };
}

type GemDepTree = DepTreeDep;

/**
 * Convert Gemfile.lock contents into a nested dependency map, matching the
 * Snyk CLI rubygems plugin (gemfile-lock-to-dependencies).
 */
function gemfileLockToDependencies(fileContents: string): {
  [name: string]: GemDepTree;
} {
  const lockFile = gemfile.interpret(fileContents, true) as LockFileMeta;

  // Malformed lockfiles that are not Gemfile.lock-shaped yield no DEPENDENCIES
  // section; skip them rather than emitting an empty graph.
  if (!lockFile.dependencies) {
    throw new Error("Invalid Gemfile.lock: missing DEPENDENCIES section");
  }

  return Object.keys(lockFile.dependencies)
    .map((dep) => dep.match(/[^!]+/)![0])
    .reduce(
      gemfileReducer(lockFile, new Map<string, GemDepTree>(), []),
      {} as { [name: string]: GemDepTree },
    );
}

function detectCycles(dep: string, chain: string[]): void {
  if (chain.indexOf(dep) >= 0) {
    throw new Error("Cyclic dependency detected in lockfile");
  }
}

function gemfileReducer(
  lockFile: LockFileMeta,
  allDeps: Map<string, GemDepTree>,
  ancestors: string[],
) {
  return (
    deps: { [name: string]: GemDepTree },
    dep: string,
  ): { [name: string]: GemDepTree } => {
    const gemspec = lockFile.specs?.[dep];
    // Specs may omit some DEPENDENCIES entries (e.g. bundler itself).
    if (gemspec) {
      detectCycles(dep, ancestors);
      if (allDeps.has(dep)) {
        deps[dep] = allDeps.get(dep)!;
      } else {
        deps[dep] = {
          name: dep,
          version: gemspec.version || "",
          dependencies: {},
        };
        allDeps.set(dep, deps[dep]);
        deps[dep].dependencies = Object.keys(gemspec)
          .filter((k) => k !== "version")
          .reduce(
            gemfileReducer(lockFile, allDeps, ancestors.concat([dep])),
            {},
          );
      }
    }
    return deps;
  };
}

export async function rubyFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  const lockPaths = findGemfileLockPaths(filePathToContent);

  for (const pathPair of lockPaths) {
    let dependencies: { [name: string]: GemDepTree };
    try {
      dependencies = gemfileLockToDependencies(
        filePathToContent[pathPair.lock],
      );
    } catch {
      // Skip malformed lockfiles so a single bad file cannot fail the scan.
      continue;
    }

    const dirName = path.basename(path.dirname(pathPair.lock));
    const depTree = {
      name: dirName && dirName !== "." && dirName !== "/" ? dirName : "app",
      dependencies,
    } as DepTreeDep;

    const depGraph = await legacy.depTreeToGraph(depTree, PACKAGE_MANAGER_TYPE);

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph,
    };

    const testedFiles = [path.basename(pathPair.lock)];
    if (pathPair.manifest) {
      testedFiles.unshift(path.basename(pathPair.manifest));
    }
    const testedFilesFact: TestedFilesFact = {
      type: "testedFiles",
      data: testedFiles,
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

function findGemfileLockPaths(
  filePathToContent: FilePathToContent,
): GemfileLockPath[] {
  const fileNamesGroupedByDirectory = groupFilesByDirectory(filePathToContent);
  const lockPaths: GemfileLockPath[] = [];

  for (const directoryPath of Object.keys(fileNamesGroupedByDirectory)) {
    const filesInDirectory = fileNamesGroupedByDirectory[directoryPath];
    const hasGemfileLock = filesInDirectory.includes("Gemfile.lock");
    if (!hasGemfileLock) {
      continue;
    }

    const lock = path.join(directoryPath, "Gemfile.lock");
    if (isInstalledGemLockfile(lock)) {
      continue;
    }

    const pair: GemfileLockPath = { lock };
    if (filesInDirectory.includes("Gemfile")) {
      pair.manifest = path.join(directoryPath, "Gemfile");
    }
    lockPaths.push(pair);
  }

  return lockPaths;
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
