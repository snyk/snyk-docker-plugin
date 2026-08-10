import { DepGraphBuilder, legacy } from "@snyk/dep-graph";
import * as path from "path";
import { DepGraphFact, TestedFilesFact } from "../../facts";

import {
  buildDepTree,
  ComposerParserResponse,
} from "@snyk/composer-lockfile-parser";
import { InvalidUserInputError } from "@snyk/composer-lockfile-parser/dist/errors";
import {
  ComposerPackage,
  parseComposerLock,
  parseInstalledJson,
} from "../../php-parser";
import { DepTreeDep } from "../../types";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

interface ProjectFiles {
  manifest?: string;
  lock?: string;
  installedJson?: string;
}
const PACKAGE_MANAGER_TYPE = "composer";

export async function phpFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const projects = groupFilesByProjectRoot(filePathToContent);

  const shouldIncludeDevDependencies = false;

  for (const project of projects.values()) {
    if (project.manifest && project.lock) {
      const manifest = project.manifest;
      const lock = project.lock;

      let parserResult: ComposerParserResponse | undefined;
      try {
        parserResult = buildDepTree(
          filePathToContent[lock],
          filePathToContent[manifest],
          manifest,
          {},
          shouldIncludeDevDependencies,
        );
      } catch (e) {
        // This will skip parsing all files that error due to being malformed.
        // If we do not do this, the entire scan will fail.
        // Ideally, we'd like to log this, but logging does not exist in this library.
        if (e instanceof InvalidUserInputError) {
          continue;
        } else {
          throw e;
        }
      }

      const depGraph = await legacy.depTreeToGraph(
        parserResult as DepTreeDep,
        PACKAGE_MANAGER_TYPE,
      );

      const depGraphFact: DepGraphFact = {
        type: "depGraph",
        data: depGraph,
      };
      const testedFilesFact: TestedFilesFact = {
        type: "testedFiles",
        data: [path.basename(manifest), path.basename(lock)],
      };
      scanResults.push({
        facts: [depGraphFact, testedFilesFact],
        identity: {
          type: depGraph.pkgManager.name,
          targetFile: lock,
        },
      });
    } else if (project.lock) {
      const packages = parseComposerLock(filePathToContent[project.lock], {
        shouldIncludeDevDependencies,
      });
      const result = buildScanResultFromPackages(packages, project.lock);
      if (result) {
        scanResults.push(result);
      }
    } else if (project.installedJson) {
      const packages = parseInstalledJson(
        filePathToContent[project.installedJson],
      );
      const result = buildScanResultFromPackages(
        packages,
        project.installedJson,
      );
      if (result) {
        scanResults.push(result);
      }
    }
    // manifest-only projects are not reported: composer.json alone carries
    // version constraints, not pinned versions, and resolving constraints is
    // out of scope.
  }

  return scanResults;
}

function buildScanResultFromPackages(
  packages: ComposerPackage[],
  targetFile: string,
): AppDepsScanResultWithoutTarget | undefined {
  if (packages.length === 0) {
    return undefined;
  }

  const builder = new DepGraphBuilder(
    { name: PACKAGE_MANAGER_TYPE },
    { name: targetFile },
  );

  for (const pkg of packages) {
    const nodeId = `${pkg.name}@${pkg.version}`;
    builder.addPkgNode({ name: pkg.name, version: pkg.version }, nodeId);
    builder.connectDep(builder.rootNodeId, nodeId);
  }

  const depGraph = builder.build();

  const depGraphFact: DepGraphFact = {
    type: "depGraph",
    data: depGraph,
  };
  const testedFilesFact: TestedFilesFact = {
    type: "testedFiles",
    data: [path.basename(targetFile)],
  };

  return {
    facts: [depGraphFact, testedFilesFact],
    identity: {
      type: depGraph.pkgManager.name,
      targetFile,
    },
  };
}

// assumption: we only care about manifest+lock files if they are in the same
// directory; vendor/composer/installed.json belongs to the project rooted two
// directories above it (<root>/vendor/composer/installed.json)
function groupFilesByProjectRoot(
  filePathToContent: FilePathToContent,
): Map<string, ProjectFiles> {
  const projects = new Map<string, ProjectFiles>();

  function projectFor(root: string): ProjectFiles {
    let project = projects.get(root);
    if (!project) {
      project = {};
      projects.set(root, project);
    }
    return project;
  }

  for (const filePath of Object.keys(filePathToContent)) {
    const fileName = path.basename(filePath);

    if (fileName === "composer.json") {
      projectFor(path.dirname(filePath)).manifest = filePath;
    } else if (fileName === "composer.lock") {
      projectFor(path.dirname(filePath)).lock = filePath;
    } else if (isVendorComposerInstalledJson(filePath)) {
      const composerDir = path.dirname(filePath);
      const vendorDir = path.dirname(composerDir);
      const projectRoot = path.dirname(vendorDir);
      projectFor(projectRoot).installedJson = filePath;
    }
  }

  return projects;
}

// Derives directory relationships with repeated path.dirname rather than
// slicing the literal string "/vendor/composer/installed.json" off the path,
// because path is platform-specific and win32 paths are backslash-separated.
function isVendorComposerInstalledJson(filePath: string): boolean {
  if (path.basename(filePath) !== "installed.json") {
    return false;
  }
  const composerDir = path.dirname(filePath);
  const vendorDir = path.dirname(composerDir);
  return (
    path.basename(composerDir) === "composer" &&
    path.basename(vendorDir) === "vendor"
  );
}
