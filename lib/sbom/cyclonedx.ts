import { randomUUID } from "crypto";

import { DockerFileAnalysis } from "../dockerfile/types";
import { DepTree, DepTreeDep } from "../types";
import { PLUGIN_VERSION } from "../version";

export interface CycloneDxComponent {
  "bom-ref": string;
  type: "library" | "container";
  name: string;
  version?: string;
  purl?: string;
  properties?: Array<{ name: string; value: string }>;
}

export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component?: CycloneDxComponent;
  };
  components: CycloneDxComponent[];
}

export interface SbomAppComponent {
  name: string;
  version?: string;
  purl?: string;
  targetFile?: string;
}

export interface SbomSource {
  imageName?: string;
  depTree?: DepTree;
  appComponents?: SbomAppComponent[];
  dockerfileAnalysis?: DockerFileAnalysis;
}

const SBOM_SOURCE_PROPERTY = "snyk:sbom:source";
const SBOM_TARGET_FILE_PROPERTY = "snyk:sbom:targetFile";

type SbomComponentSource = "image" | "application" | "dockerfile";

/**
 * Mutable accumulator for a single CycloneDX component while we merge
 * evidence from multiple sources (image, application, dockerfile) before
 * emitting the final read-only CycloneDxComponent objects.
 */
interface ComponentAccumulator {
  type: "library" | "container";
  name: string;
  version?: string;
  purl?: string;
  sources: Set<SbomComponentSource>;
  targetFiles: Set<string>;
}

/**
 * Builds a CycloneDX 1.6 JSON BOM from whichever inputs were available for
 * this scan. Any combination of `depTree`, `appComponents` and
 * `dockerfileAnalysis` may be supplied; callers decide which sources apply.
 *
 * Dockerfile-installed packages carry no version (see `DockerFilePackages`),
 * so a package discovered both in the image and in a `RUN` instruction is
 * folded into a single component whose `snyk:sbom:source` property lists
 * both origins, rather than appearing twice.
 */
export function buildCycloneDxBom(source: SbomSource): CycloneDxBom {
  // Keyed by `name@version` for sources that carry a version (image,
  // application). Also indexed by name alone so that dockerfile packages,
  // which have no version, can still be matched against an existing
  // component discovered through another source.
  const byNameAndVersion = new Map<string, ComponentAccumulator>();
  const byName = new Map<string, ComponentAccumulator>();

  const upsertComponent = (
    type: "library" | "container",
    name: string,
    version: string | undefined,
    purl: string | undefined,
    componentSource: SbomComponentSource,
    targetFile?: string,
  ): void => {
    const versionKey = `${name}@${version ?? ""}`;
    let existing = byNameAndVersion.get(versionKey);

    // A dockerfile package has no version, so fall back to matching by
    // name alone against whatever component we already know about.
    if (!existing && version === undefined) {
      existing = byName.get(name);
    }

    if (existing) {
      existing.sources.add(componentSource);
      if (targetFile) {
        existing.targetFiles.add(targetFile);
      }
      if (!existing.purl && purl) {
        existing.purl = purl;
      }
      if (!existing.version && version) {
        existing.version = version;
      }
      return;
    }

    const created: ComponentAccumulator = {
      type,
      name,
      version,
      purl,
      sources: new Set([componentSource]),
      targetFiles: new Set(targetFile ? [targetFile] : []),
    };
    byNameAndVersion.set(versionKey, created);
    if (!byName.has(name)) {
      byName.set(name, created);
    }
  };

  if (source.depTree) {
    for (const dep of flattenDepTree(source.depTree)) {
      upsertComponent("library", dep.name, dep.version, dep.purl, "image");
    }
  }

  for (const appComponent of source.appComponents ?? []) {
    upsertComponent(
      "library",
      appComponent.name,
      appComponent.version,
      appComponent.purl,
      "application",
      appComponent.targetFile,
    );
  }

  const dockerfilePackages =
    source.dockerfileAnalysis?.dockerfilePackages ?? {};
  for (const name of Object.keys(dockerfilePackages)) {
    upsertComponent("library", name, undefined, undefined, "dockerfile");
  }

  const orderedComponents = [...byNameAndVersion.values()];

  const usedBomRefs = new Set<string>();
  const components: CycloneDxComponent[] = orderedComponents.map(
    (accumulator) => finalizeComponent(accumulator, usedBomRefs),
  );

  if (source.dockerfileAnalysis?.baseImage) {
    components.push(
      finalizeComponent(
        {
          type: "container",
          name: source.dockerfileAnalysis.baseImage,
          version: undefined,
          purl: undefined,
          sources: new Set(["dockerfile"]),
          targetFiles: new Set(),
        },
        usedBomRefs,
      ),
    );
  }

  const metadataComponent: CycloneDxComponent | undefined = source.imageName
    ? {
        "bom-ref": makeUniqueBomRef(source.imageName, undefined, usedBomRefs),
        type: "container",
        name: source.imageName,
      }
    : undefined;

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "Snyk",
          name: "snyk-docker-plugin",
          version: PLUGIN_VERSION,
        },
      ],
      ...(metadataComponent ? { component: metadataComponent } : {}),
    },
    components,
  };
}

function finalizeComponent(
  accumulator: ComponentAccumulator,
  usedBomRefs: Set<string>,
): CycloneDxComponent {
  const properties = [...accumulator.sources].sort(bySourcePriority).join(",");

  const component: CycloneDxComponent = {
    "bom-ref": makeUniqueBomRef(
      accumulator.name,
      accumulator.version,
      usedBomRefs,
    ),
    type: accumulator.type,
    name: accumulator.name,
    ...(accumulator.version ? { version: accumulator.version } : {}),
    ...(accumulator.purl ? { purl: accumulator.purl } : {}),
  };

  const propertyList: Array<{ name: string; value: string }> = [];
  if (properties) {
    propertyList.push({ name: SBOM_SOURCE_PROPERTY, value: properties });
  }
  if (accumulator.targetFiles.size > 0) {
    propertyList.push({
      name: SBOM_TARGET_FILE_PROPERTY,
      value: [...accumulator.targetFiles].join(","),
    });
  }
  if (propertyList.length > 0) {
    component.properties = propertyList;
  }

  return component;
}

// Keeps the "snyk:sbom:source" property value deterministic
// (e.g. always "image,dockerfile", never "dockerfile,image").
const SOURCE_PRIORITY: SbomComponentSource[] = [
  "image",
  "application",
  "dockerfile",
];
function bySourcePriority(
  a: SbomComponentSource,
  b: SbomComponentSource,
): number {
  return SOURCE_PRIORITY.indexOf(a) - SOURCE_PRIORITY.indexOf(b);
}

function makeUniqueBomRef(
  name: string,
  version: string | undefined,
  usedBomRefs: Set<string>,
): string {
  const base = version ? `${name}@${version}` : name;
  let candidate = base;
  let suffix = 2;
  while (usedBomRefs.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix++;
  }
  usedBomRefs.add(candidate);
  return candidate;
}

/** Walks a (possibly cyclic-by-name) DepTree and yields every dependency node once, keyed by name+version. */
function flattenDepTree(tree: DepTree): DepTreeDep[] {
  const seen = new Set<string>();
  const result: DepTreeDep[] = [];

  const visit = (node: DepTreeDep) => {
    const key = `${node.name}@${node.version}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    result.push(node);

    for (const childName of Object.keys(node.dependencies ?? {})) {
      visit(node.dependencies[childName]);
    }
  };

  for (const childName of Object.keys(tree.dependencies ?? {})) {
    visit(tree.dependencies[childName]);
  }

  return result;
}
