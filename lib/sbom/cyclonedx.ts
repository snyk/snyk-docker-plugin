import { DepGraph } from "@snyk/dep-graph";
import {
  CycloneDxComponent,
  CycloneDxDocument,
  DepGraphsToCycloneDxOptions,
} from "./types";

function buildBomRef(
  pkgManagerName: string,
  name: string,
  version?: string | null,
): string {
  if (version) {
    return `${pkgManagerName}:${name}@${version}`;
  }

  return `${pkgManagerName}:${name}`;
}

function pkgToComponent(
  graph: DepGraph,
  pkg: { name: string; version?: string | null },
): CycloneDxComponent {
  const bomRef = buildBomRef(graph.pkgManager.name, pkg.name, pkg.version);
  const component: CycloneDxComponent = {
    type: "library",
    name: pkg.name,
    "bom-ref": bomRef,
  };

  if (pkg.version) {
    component.version = pkg.version;
  }

  return component;
}

export function depGraphsToCycloneDx(
  graphs: DepGraph | DepGraph[],
  options?: DepGraphsToCycloneDxOptions,
): CycloneDxDocument {
  const graphList = Array.isArray(graphs) ? graphs : [graphs];

  // Components from all graphs are merged; entries sharing the same bom-ref
  // (pkgManager.name:name or pkgManager.name:name@version) collapse to one.
  const componentsByRef = new Map<string, CycloneDxComponent>();

  for (const graph of graphList) {
    for (const pkg of graph.getDepPkgs()) {
      const component = pkgToComponent(graph, pkg);
      if (!componentsByRef.has(component["bom-ref"])) {
        componentsByRef.set(component["bom-ref"], component);
      }
    }
  }

  const document: CycloneDxDocument = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    components: Array.from(componentsByRef.values()),
  };

  if (options?.serialNumber) {
    document.serialNumber = options.serialNumber;
  }

  if (options?.timestamp) {
    document.metadata = { timestamp: options.timestamp };
  }

  return document;
}
