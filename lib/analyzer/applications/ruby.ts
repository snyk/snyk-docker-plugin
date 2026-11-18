import { legacy } from "@snyk/dep-graph";
import * as gemfile from "@snyk/gemfile";
import * as Debug from "debug";
import { posix as path } from "path";
import { getErrorMessage } from "../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { DepTreeDep } from "../../types";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const debug = Debug("snyk");
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
  return INSTALLED_GEM_LOCKFILE.test(toPosix(filePath));
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
 * @snyk/gemfile writes console.warn for malformed lockfiles. Route that to
 * the debug logger so scans do not spam the user's terminal.
 */
function interpretGemfileLock(fileContents: string): LockFileMeta {
  const originalWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    debug(`@snyk/gemfile: ${args.map(String).join(" ")}`);
  };
  try {
    return gemfile.interpret(fileContents, true) as LockFileMeta;
  } finally {
    console.warn = originalWarn;
  }
}

/**
 * Convert Gemfile.lock contents into a nested dependency map, matching the
 * Snyk CLI rubygems plugin (gemfile-lock-to-dependencies).
 */
function gemfileLockToDependencies(fileContents: string): {
  [name: string]: GemDepTree;
} {
  const lockFile = interpretGemfileLock(fileContents);

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

function toPosix(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function fileBasename(filePath: string): string {
  return path.basename(toPosix(filePath));
}

/**
 * Swap the trailing basename while preserving the original key's separators,
 * so lookups hit filePathToContent whether keys are POSIX or Windows-style.
 */
function replaceBasename(filePath: string, newBasename: string): string {
  const base = fileBasename(filePath);
  return filePath.slice(0, filePath.length - base.length) + newBasename;
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
    } catch (error) {
      // Skip malformed lockfiles so a single bad file cannot fail the scan.
      debug(
        `Skipping Gemfile.lock at ${pathPair.lock}: ${getErrorMessage(error)}`,
      );
      continue;
    }

    const parentDir = path.basename(path.dirname(toPosix(pathPair.lock)));
    const depTree = {
      name:
        parentDir && parentDir !== "." && parentDir !== "/" ? parentDir : "app",
      dependencies,
    } as DepTreeDep;

    const depGraph = await legacy.depTreeToGraph(depTree, PACKAGE_MANAGER_TYPE);

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph,
    };

    const testedFiles = [fileBasename(pathPair.lock)];
    if (pathPair.manifest) {
      testedFiles.unshift(fileBasename(pathPair.manifest));
    }
    const testedFilesFact: TestedFilesFact = {
      type: "testedFiles",
      data: testedFiles,
    };

    scanResults.push({
      facts: [depGraphFact, testedFilesFact],
      identity: {
        type: depGraph.pkgManager.name,
        // Keep the original map key (POSIX or Windows) for consumers.
        targetFile: pathPair.lock,
      },
    });
  }

  return scanResults;
}

/**
 * Prefer the original filePathToContent keys over path.join rebuilds.
 * Host path.join turns "/app/Gemfile.lock" into "\\app\\Gemfile.lock" on
 * Windows; extractor keys may also already be Windows-style. Either way,
 * rebuilding breaks the lookup.
 */
function findGemfileLockPaths(
  filePathToContent: FilePathToContent,
): GemfileLockPath[] {
  const lockPaths: GemfileLockPath[] = [];

  for (const filePath of Object.keys(filePathToContent)) {
    if (fileBasename(filePath) !== "Gemfile.lock") {
      continue;
    }
    if (isInstalledGemLockfile(filePath)) {
      continue;
    }

    const pair: GemfileLockPath = { lock: filePath };
    const manifestPath = replaceBasename(filePath, "Gemfile");
    if (filePathToContent[manifestPath] !== undefined) {
      pair.manifest = manifestPath;
    }
    lockPaths.push(pair);
  }

  return lockPaths;
}
