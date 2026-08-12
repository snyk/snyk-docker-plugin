import { DepGraph } from "@snyk/dep-graph";
import { PackageURL } from "packageurl-js";
import {
  CycloneDxComponent,
  CycloneDxDocument,
  DepGraphsToCycloneDxOptions,
} from "./types";

// Purl types per https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst,
// keyed by the pkgManager.name values this repo's dep-graph builders emit. A manager
// with no entry here omits the purl rather than emit a bogus type.
const PURL_TYPE_BY_PKG_MANAGER: Record<string, string> = {
  deb: "deb",
  apk: "apk",
  rpm: "rpm",
  npm: "npm",
  pip: "pypi",
  nuget: "nuget",
  golang: "golang",
  maven: "maven",
  composer: "composer",
  gem: "gem",
};

function buildPurl(
  pkgManagerName: string,
  name: string,
  version?: string | null,
): string | undefined {
  const purlType = PURL_TYPE_BY_PKG_MANAGER[pkgManagerName];
  if (!purlType) {
    return undefined;
  }

  // component.name keeps the dep-graph package name verbatim (e.g. the
  // `source/binary` form minted by depFullName); the purl only wants the
  // last segment.
  const purlName = name.slice(name.lastIndexOf("/") + 1);

  return new PackageURL(
    purlType,
    undefined,
    purlName,
    version ?? undefined,
    undefined,
    undefined,
  ).toString();
}

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

  const purl = buildPurl(graph.pkgManager.name, pkg.name, pkg.version);
  if (purl) {
    component.purl = purl;
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
