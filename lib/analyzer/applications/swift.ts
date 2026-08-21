import { DepGraphBuilder } from "@snyk/dep-graph";
import * as Debug from "debug";
import * as path from "path";
import { getErrorMessage } from "../../error-utils";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "./types";

const debug = Debug("snyk");

interface SwiftPinState {
  version?: string;
}

interface SwiftPinV1 {
  package: string;
  repositoryURL: string;
  state?: SwiftPinState;
}

interface PackageResolvedV1 {
  version: 1;
  object?: { pins: SwiftPinV1[] };
}

interface SwiftPinV2 {
  identity: string;
  location: string;
  state?: SwiftPinState;
}

interface PackageResolvedV2 {
  version: 2 | 3;
  pins: SwiftPinV2[];
}

type PackageResolved = PackageResolvedV1 | PackageResolvedV2;

interface ResolvedPin {
  name: string;
  version?: string;
}

function nameFromUrl(url: string): string {
  const base = path.basename(url);
  const trimmed = base.endsWith(".git") ? base.slice(0, -".git".length) : base;
  return trimmed.toLowerCase();
}

function extractPins(parsed: PackageResolved): ResolvedPin[] {
  if (parsed.version === 1) {
    const pins = parsed.object?.pins ?? [];
    return pins.map((pin) => ({
      name: pin.repositoryURL ? nameFromUrl(pin.repositoryURL) : pin.package,
      version: pin.state?.version,
    }));
  }
  if (parsed.version === 2 || parsed.version === 3) {
    const pins = parsed.pins ?? [];
    return pins.map((pin) => ({
      name: pin.identity || (pin.location ? nameFromUrl(pin.location) : ""),
      version: pin.state?.version,
    }));
  }
  throw new Error(
    `Unrecognised Package.resolved version: ${
      (parsed as { version?: unknown }).version
    }`,
  );
}

/**
 * Creates a flat dep graph for every Package.resolved file that was found.
 * Package.resolved carries no dependency edges between pinned packages, so
 * every pin is a direct child of the root - see the Swift ecosystem non-goal.
 */
export async function swiftFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, content] of Object.entries(filePathToContent)) {
    try {
      const parsed: PackageResolved = JSON.parse(content);
      const pins = extractPins(parsed);

      const builder = new DepGraphBuilder(
        { name: "swift" },
        { name: filePath },
      );

      let pinnedCount = 0;
      for (const pin of pins) {
        if (!pin.name || !pin.version) {
          // A pin with no resolved version is a branch/revision pin; it can't
          // be matched against advisory data, so it's skipped.
          continue;
        }
        const nodeId = `${pin.name}@${pin.version}`;
        builder.addPkgNode({ name: pin.name, version: pin.version }, nodeId);
        builder.connectDep(builder.rootNodeId, nodeId);
        pinnedCount++;
      }

      if (pinnedCount === 0) {
        debug(`No versioned pins found in Package.resolved: ${filePath}`);
        continue;
      }

      const depGraphFact: DepGraphFact = {
        type: "depGraph",
        data: builder.build(),
      };
      const testedFilesFact: TestedFilesFact = {
        type: "testedFiles",
        data: [path.basename(filePath)],
      };
      scanResults.push({
        facts: [depGraphFact, testedFilesFact],
        identity: {
          type: "swift",
          targetFile: filePath,
        },
      });
    } catch (err) {
      debug(
        `Failed to parse Package.resolved at ${filePath}: ${getErrorMessage(
          err,
        )}`,
      );
    }
  }

  return scanResults;
}
