import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import { eventLoopSpinner } from "event-loop-spinner";
import * as path from "path";
import * as semver from "semver";
import { DepGraphFact } from "../../../facts";
import { getPackageInfo } from "../../../python-parser/metadata-parser";
import { getRequirements } from "../../../python-parser/requirements-parser";
import {
  PythonMetadataFiles,
  PythonPackage,
  PythonRequirement,
} from "../../../python-parser/types";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";

const debug = Debug("snyk");
class PythonDepGraphBuilder {
  private requirements: PythonRequirement[];
  private metadata: PythonMetadataFiles;
  private builder: DepGraphBuilder;
  private visitedMap: Set<string> = new Set();

  constructor(
    name: string,
    requirements: PythonRequirement[],
    metadata: PythonMetadataFiles,
  ) {
    this.requirements = requirements;
    this.metadata = metadata;
    this.builder = new DepGraphBuilder({ name: "pip" }, { name });
  }

  public async build(): Promise<DepGraph> {
    for (const dep of this.requirements) {
      await this.addDependenciesToDepGraph(this.builder.rootNodeId, dep);
    }
    return this.builder.build();
  }

  // depth-first search for dependencies and assigning them to the dep graph builder
  private async addDependenciesToDepGraph(
    root: string,
    req: PythonRequirement,
  ): Promise<void> {
    if (eventLoopSpinner.isStarving()) {
      await eventLoopSpinner.spin();
    }
    const metadata = this.findMetadata(req);
    if (!metadata) {
      return;
    }
    const nodeId = `${metadata.name}@${metadata.version}`;
    if (!this.visitedMap.has(nodeId)) {
      this.visitedMap.add(nodeId);
      this.builder.addPkgNode(
        { name: metadata.name, version: metadata.version },
        nodeId,
      );
      for (const dep of metadata.dependencies) {
        await this.addDependenciesToDepGraph(nodeId, dep);
      }
    }
    this.builder.connectDep(root, nodeId);
  }

  // find the best match for a dependency in found metadata files
  private findMetadata(dep: PythonRequirement): PythonPackage | null {
    const nameMatches = this.metadata[dep.name.toLowerCase()];
    if (!nameMatches || nameMatches.length === 0) {
      return null;
    }
    if (nameMatches.length === 1 || !dep.version) {
      return nameMatches[0];
    }
    for (const meta of nameMatches) {
      if (
        semver.satisfies(meta.version, `${dep.specifier}${dep.version}`, true)
      ) {
        return meta;
      }
    }
    // fallback to the first metadata file if no match is found
    return nameMatches[0];
  }
}

/**
 * Creates a dep graph for every requirements.txt file that was found
 */
export async function pipFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  const requirements = {};
  const metadataItems: PythonMetadataFiles = {};
  for (const filepath of Object.keys(filePathToContent)) {
    const fileBaseName = path.basename(filepath);
    if (fileBaseName === "requirements.txt") {
      requirements[filepath] = getRequirements(filePathToContent[filepath]);
    } else if (fileBaseName === "METADATA") {
      try {
        const packageInfo = getPackageInfo(filePathToContent[filepath]);
        if (!metadataItems[packageInfo.name.toLowerCase()]) {
          metadataItems[packageInfo.name.toLowerCase()] = [];
        }
        metadataItems[packageInfo.name.toLowerCase()].push(packageInfo);
      } catch (err) {
        debug(err.message);
      }
    }
  }
  if (Object.keys(metadataItems).length === 0) {
    return scanResults;
  }
  // pre-sort each package name by version, descending
  for (const name of Object.keys(metadataItems)) {
    metadataItems[name].sort((v1, v2) => {
      return semver.rcompare(v1.version, v2.version);
    });
  }

  for (const requirementsFile of Object.keys(requirements)) {
    if (requirements[requirementsFile].length === 0) {
      continue;
    }
    const builder = new PythonDepGraphBuilder(
      requirementsFile,
      requirements[requirementsFile],
      metadataItems,
    );
    const depGraph = await builder.build();
    if (!depGraph) {
      continue;
    }

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph,
    };
    scanResults.push({
      facts: [depGraphFact],
      identity: {
        type: "pip",
        targetFile: requirementsFile,
      },
    });
  }
  return scanResults;
}
