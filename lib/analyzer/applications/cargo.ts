import { DepGraphBuilder } from "@snyk/dep-graph";
import * as path from "path";

import { parseCargoLock } from "../../cargo-parser/cargo-lock-parser";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const PACKAGE_MANAGER_TYPE = "cargo";

export async function cargoFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, content] of Object.entries(filePathToContent)) {
    if (path.basename(filePath) !== "Cargo.lock") {
      continue;
    }

    const scanResult = buildScanResultFromLock(content, filePath);
    if (scanResult) {
      scanResults.push(scanResult);
    }
  }

  return scanResults;
}

function buildScanResultFromLock(
  content: string,
  targetFile: string,
): AppDepsScanResultWithoutTarget | undefined {
  const packages = parseCargoLock(content);
  if (packages.length === 0) {
    return undefined;
  }

  const builder = new DepGraphBuilder(
    { name: PACKAGE_MANAGER_TYPE },
    { name: targetFile },
  );

  const seenNodeIds = new Set<string>();

  for (const pkg of packages) {
    const nodeId = `${pkg.name}@${pkg.version}`;
    if (seenNodeIds.has(nodeId)) {
      continue;
    }
    seenNodeIds.add(nodeId);

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
