import { DepGraphBuilder } from "@snyk/dep-graph";
import { buildResponse } from "../../lib/response-builder";
import { CycloneDxBom } from "../../lib/sbom/cyclonedx";
import { DepTreeDep } from "../../lib/types";

class NodeBuilder {
  private node: DepTreeDep;

  constructor(name: string, version = "1.0") {
    this.node = { name, version, dependencies: {} };
  }

  public withChild(child: NodeBuilder): NodeBuilder {
    this.node.dependencies[child.node.name] = child.build();
    return this;
  }

  public build(): DepTreeDep {
    return this.node;
  }
}

const node = (name: string, version?: string) => new NodeBuilder(name, version);

const createMockAnalysis = (overrides: Record<string, unknown> = {}) => ({
  depTree: {
    dependencies: {},
    name: "test",
    version: "1.0.0",
    packageFormatVersion: "1.0.0",
    targetOS: {
      prettyName: "Test OS",
    },
  },
  packageFormat: "test",
  manifestFiles: [],
  applicationDependenciesScanResults: [],
  ...overrides,
});

const getSbomFacts = (scanResult: {
  facts?: Array<{ type: string; data: any }>;
}): Array<{ type: string; data: CycloneDxBom }> =>
  (scanResult.facts ?? []).filter((fact) => fact.type === "sbom") as Array<{
    type: string;
    data: CycloneDxBom;
  }>;

const componentNames = (bom: CycloneDxBom): string[] =>
  bom.components.map((component) => component.name);

const findProperty = (
  component: CycloneDxBom["components"][number],
  name: string,
): string | undefined =>
  component.properties?.find((property) => property.name === name)?.value;

function buildDepGraph(pkgs: Array<{ name: string; version: string }>) {
  const builder = new DepGraphBuilder(
    { name: "npm" },
    { name: "root-project", version: "1.0.0" },
  );
  for (const pkg of pkgs) {
    const nodeId = `${pkg.name}@${pkg.version}`;
    builder.addPkgNode(pkg, nodeId);
    builder.connectDep(builder.rootNodeId, nodeId);
  }
  return builder.build();
}

describe("buildResponse sbom wiring", () => {
  describe("with sbom enabled", () => {
    it("emits exactly one sbom fact naming the depTree packages when there is no dockerfileAnalysis", async () => {
      const mockAnalysis = createMockAnalysis({
        depTree: {
          dependencies: {
            openssl: node("openssl", "3.0.11-1").build(),
            curl: node("curl", "8.4.0-1").build(),
          },
          name: "test-image",
          version: "1.0.0",
          packageFormatVersion: "deb:0.0.1",
          targetOS: { prettyName: "Debian" },
        },
        packageFormat: "deb",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        undefined,
        undefined,
        {
          sbom: true,
        },
      );

      const sbomFacts = getSbomFacts(result.scanResults[0]);
      expect(sbomFacts).toHaveLength(1);

      const bom = sbomFacts[0].data;
      expect(componentNames(bom)).toEqual(
        expect.arrayContaining(["openssl", "curl"]),
      );

      const openssl = bom.components.find((c) => c.name === "openssl");
      expect(openssl?.purl).toBeUndefined();
    });

    it("keeps a depTree node's purl on the matching component", async () => {
      const depWithPurl: DepTreeDep = {
        name: "openssl",
        version: "3.0.11-1",
        purl: "pkg:deb/debian/openssl@3.0.11-1",
        dependencies: {},
      };

      const mockAnalysis = createMockAnalysis({
        depTree: {
          dependencies: { openssl: depWithPurl },
          name: "test-image",
          version: "1.0.0",
          packageFormatVersion: "deb:0.0.1",
          targetOS: { prettyName: "Debian" },
        },
        packageFormat: "deb",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        undefined,
        undefined,
        {
          sbom: true,
        },
      );

      const bom = getSbomFacts(result.scanResults[0])[0].data;
      const openssl = bom.components.find((c) => c.name === "openssl");
      expect(openssl?.purl).toBe("pkg:deb/debian/openssl@3.0.11-1");
    });

    it("includes application dep-graph packages and named jars, tagged with the application source, and omits nameless jars", async () => {
      const appDepGraph = buildDepGraph([
        { name: "lodash", version: "4.17.21" },
        { name: "left-pad", version: "1.3.0" },
      ]);

      const mockAnalysis = createMockAnalysis({
        applicationDependenciesScanResults: [
          {
            facts: [
              { type: "depGraph", data: appDepGraph },
              {
                type: "jarFingerprints",
                data: {
                  fingerprints: [
                    {
                      location: "/app/lib/named.jar",
                      digest: "abc123",
                      name: "com.example:named",
                      version: "1.2.3",
                      dependencies: [],
                    },
                    {
                      location: "/app/lib/unresolved.jar",
                      digest: "def456",
                      dependencies: [],
                    },
                  ],
                  origin: "test",
                  path: "/app/lib",
                },
              },
            ],
            identity: { type: "npm", targetFile: "/app/package-lock.json" },
            target: { image: "test-app" },
          },
        ],
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        undefined,
        undefined,
        {
          sbom: true,
        },
      );

      // Exactly one sbom fact overall, and it lives on the first (OS) scan
      // result — not duplicated onto the application scan result.
      expect(result.scanResults).toHaveLength(2);
      expect(getSbomFacts(result.scanResults[0])).toHaveLength(1);
      expect(getSbomFacts(result.scanResults[1])).toHaveLength(0);

      const bom = getSbomFacts(result.scanResults[0])[0].data;
      const names = componentNames(bom);

      expect(names).toEqual(
        expect.arrayContaining(["lodash", "left-pad", "com.example:named"]),
      );
      expect(names).not.toContain("unresolved.jar");
      expect(names.filter((n) => n === "com.example:named")).toHaveLength(1);

      for (const name of ["lodash", "left-pad", "com.example:named"]) {
        const component = bom.components.find((c) => c.name === name);
        expect(findProperty(component!, "snyk:sbom:source")).toBe(
          "application",
        );
      }
    });

    it("merges image, application and dockerfile components into a single sbom fact with no duplicated name@version", async () => {
      const appDepGraph = buildDepGraph([
        { name: "lodash", version: "4.17.21" },
      ]);

      const mockAnalysis = createMockAnalysis({
        depTree: {
          dependencies: {
            curl: node("curl", "8.4.0-1").build(),
            openssl: node("openssl", "3.0.11-1").build(),
          },
          name: "test-image",
          version: "1.0.0",
          packageFormatVersion: "deb:0.0.1",
          targetOS: { prettyName: "Debian" },
        },
        packageFormat: "deb",
        applicationDependenciesScanResults: [
          {
            facts: [{ type: "depGraph", data: appDepGraph }],
            identity: { type: "npm", targetFile: "/app/package-lock.json" },
            target: { image: "test-app" },
          },
        ],
      });

      const dockerfileAnalysis = {
        baseImage: "debian:12",
        dockerfilePackages: {
          curl: { instruction: "RUN", installCommand: "apt-get install curl" },
          git: { instruction: "RUN", installCommand: "apt-get install git" },
        },
        dockerfileLayers: {},
      };

      const result = await buildResponse(
        mockAnalysis as any,
        dockerfileAnalysis as any,
        false,
        undefined,
        undefined,
        { sbom: true },
      );

      const sbomFacts = getSbomFacts(result.scanResults[0]);
      expect(sbomFacts).toHaveLength(1);

      const bom = sbomFacts[0].data;
      const names = componentNames(bom);
      expect(new Set(names).size).toBe(names.length);

      expect(names).toEqual(
        expect.arrayContaining([
          "curl",
          "openssl",
          "lodash",
          "git",
          "debian:12",
        ]),
      );

      const curl = bom.components.find((c) => c.name === "curl");
      expect(findProperty(curl!, "snyk:sbom:source")).toBe("image,dockerfile");

      const openssl = bom.components.find((c) => c.name === "openssl");
      expect(findProperty(openssl!, "snyk:sbom:source")).toBe("image");

      const lodash = bom.components.find((c) => c.name === "lodash");
      expect(findProperty(lodash!, "snyk:sbom:source")).toBe("application");

      const git = bom.components.find((c) => c.name === "git");
      expect(findProperty(git!, "snyk:sbom:source")).toBe("dockerfile");

      expect(bom.metadata.component).toBeDefined();
      expect(bom.metadata.component?.type).toBe("container");
      expect(bom.metadata.component?.name).toBe("test-image");
    });

    it("suffixes metadata.component's bom-ref when it collides with a same-named dockerfile base-image component", async () => {
      const mockAnalysis = createMockAnalysis({
        depTree: {
          dependencies: {},
          // depGraph.rootPkg.name (and thus sbomSource.imageName) is
          // derived from depTree.name, so this matches the
          // dockerfileAnalysis.baseImage below.
          name: "node:18-alpine",
          version: "1.0.0",
          packageFormatVersion: "deb:0.0.1",
          targetOS: { prettyName: "Debian" },
        },
        packageFormat: "deb",
      });

      const dockerfileAnalysis = {
        baseImage: "node:18-alpine",
        dockerfilePackages: {},
        dockerfileLayers: {},
      };

      const result = await buildResponse(
        mockAnalysis as any,
        dockerfileAnalysis as any,
        false,
        undefined,
        undefined,
        { sbom: true },
      );

      const bom = getSbomFacts(result.scanResults[0])[0].data;

      const baseImageComponent = bom.components.find(
        (c) => c.name === "node:18-alpine",
      );
      expect(baseImageComponent).toBeDefined();

      const metadataComponent = bom.metadata.component!;
      expect(metadataComponent).toBeDefined();
      expect(metadataComponent.name).toBe("node:18-alpine");
      expect(metadataComponent["bom-ref"]).not.toBe(
        baseImageComponent!["bom-ref"],
      );
    });

    it('treats the string "true" the same as boolean true', async () => {
      const mockAnalysis = createMockAnalysis({
        depTree: {
          dependencies: { openssl: node("openssl", "3.0.11-1").build() },
          name: "test-image",
          version: "1.0.0",
          packageFormatVersion: "deb:0.0.1",
          targetOS: { prettyName: "Debian" },
        },
        packageFormat: "deb",
      });

      const result = await buildResponse(
        mockAnalysis as any,
        undefined,
        false,
        undefined,
        undefined,
        {
          sbom: "true",
        },
      );

      expect(getSbomFacts(result.scanResults[0])).toHaveLength(1);
    });
  });

  describe("with sbom absent", () => {
    it("emits no sbom fact on any scan result and leaves the OS scan result's fact list unchanged", async () => {
      const mockAnalysis = createMockAnalysis({
        depTree: {
          dependencies: { openssl: node("openssl", "3.0.11-1").build() },
          name: "test-image",
          version: "1.0.0",
          packageFormatVersion: "deb:0.0.1",
          targetOS: { prettyName: "Debian" },
        },
        packageFormat: "deb",
        applicationDependenciesScanResults: [
          {
            facts: [{ type: "depGraph", data: buildDepGraph([]) }],
            identity: { type: "npm" },
            target: { image: "test-app" },
          },
        ],
      });

      const result = await buildResponse(mockAnalysis as any, undefined, false);

      for (const scanResult of result.scanResults) {
        expect(getSbomFacts(scanResult)).toHaveLength(0);
      }

      expect(result.scanResults[0].facts.map((fact) => fact.type)).toEqual([
        "depGraph",
        "imageOsReleasePrettyName",
        "pluginVersion",
      ]);
    });
  });
});
