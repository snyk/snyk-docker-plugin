import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
import { depGraphsToCycloneDx } from "../../../lib/sbom/cyclonedx";

function buildGraph(
  pkgManagerName: string,
  rootName: string,
  deps: Array<{ name: string; version?: string }>,
): DepGraph {
  const builder = new DepGraphBuilder(
    { name: pkgManagerName },
    { name: rootName, version: "0.0.0" },
  );

  deps.forEach((dep, index) => {
    const nodeId = `node-${index}`;
    builder.addPkgNode({ name: dep.name, version: dep.version }, nodeId);
    builder.connectDep(builder.rootNodeId, nodeId);
  });

  return builder.build();
}

describe("depGraphsToCycloneDx", () => {
  it("emits the required top-level CycloneDX fields", () => {
    const graph = buildGraph("npm", "app", []);

    const document = depGraphsToCycloneDx(graph);

    expect(document.bomFormat).toBe("CycloneDX");
    expect(document.specVersion).toBe("1.5");
    expect(document.version).toBe(1);
  });

  it("returns an empty components array when given an empty list of graphs", () => {
    const document = depGraphsToCycloneDx([]);

    expect(document.components).toEqual([]);
  });

  it("builds a bom-ref of pkgManager:name@version and includes the purl for a mapped package manager", () => {
    const graph = buildGraph("npm", "root-app", [
      { name: "lodash", version: "4.17.21" },
    ]);

    const document = depGraphsToCycloneDx(graph);

    expect(document.components).toEqual([
      {
        type: "library",
        name: "lodash",
        version: "4.17.21",
        purl: "pkg:npm/lodash@4.17.21",
        "bom-ref": "npm:lodash@4.17.21",
      },
    ]);
  });

  it("omits the version key and the bom-ref version suffix when a package has no version", () => {
    const graph = buildGraph("pip", "root-app", [{ name: "some-pkg" }]);

    const document = depGraphsToCycloneDx(graph);

    expect(document.components).toEqual([
      {
        type: "library",
        name: "some-pkg",
        purl: "pkg:pypi/some-pkg",
        "bom-ref": "pip:some-pkg",
      },
    ]);
  });

  it("omits purl for a package manager with no known purl type mapping", () => {
    const graph = buildGraph("pnpm", "root-app", [
      { name: "widget", version: "1.0.0" },
    ]);

    const document = depGraphsToCycloneDx(graph);

    expect(document.components).toEqual([
      {
        type: "library",
        name: "widget",
        version: "1.0.0",
        "bom-ref": "pnpm:widget@1.0.0",
      },
    ]);
  });

  it("omits purl for yarn components, which have no purl type mapping", () => {
    const graph = buildGraph("yarn", "root-app", [
      { name: "widget", version: "1.0.0" },
    ]);

    const document = depGraphsToCycloneDx(graph);

    expect(document.components).toEqual([
      {
        type: "library",
        name: "widget",
        version: "1.0.0",
        "bom-ref": "yarn:widget@1.0.0",
      },
    ]);
  });

  it("omits purl for poetry components, which have no purl type mapping", () => {
    const graph = buildGraph("poetry", "root-app", [
      { name: "widget", version: "1.0.0" },
    ]);

    const document = depGraphsToCycloneDx(graph);

    expect(document.components).toEqual([
      {
        type: "library",
        name: "widget",
        version: "1.0.0",
        "bom-ref": "poetry:widget@1.0.0",
      },
    ]);
  });

  it("keeps the verbatim source/binary name on the component while the purl only uses the segment after the last '/'", () => {
    const graph = buildGraph("deb", "os", [
      { name: "glibc/libc-bin", version: "2.31" },
    ]);

    const document = depGraphsToCycloneDx(graph);

    expect(document.components).toEqual([
      {
        type: "library",
        name: "glibc/libc-bin",
        version: "2.31",
        purl: "pkg:deb/libc-bin@2.31",
        "bom-ref": "deb:glibc/libc-bin@2.31",
      },
    ]);
  });

  it("dedupes components sharing the same bom-ref across multiple graphs", () => {
    const graphA = buildGraph("npm", "app-a", [
      { name: "shared-lib", version: "1.0.0" },
    ]);
    const graphB = buildGraph("npm", "app-b", [
      { name: "shared-lib", version: "1.0.0" },
    ]);

    const document = depGraphsToCycloneDx([graphA, graphB]);

    expect(document.components).toHaveLength(1);
    expect(document.components[0]["bom-ref"]).toBe("npm:shared-lib@1.0.0");
  });

  it("keeps components as distinct entries when the same name@version appears under different package managers", () => {
    const graphA = buildGraph("pip", "app", [
      { name: "requests", version: "2.31.0" },
    ]);
    const graphB = buildGraph("deb", "os", [
      { name: "requests", version: "2.31.0" },
    ]);

    const document = depGraphsToCycloneDx([graphA, graphB]);

    expect(document.components.map((c) => c["bom-ref"]).sort()).toEqual([
      "deb:requests@2.31.0",
      "pip:requests@2.31.0",
    ]);
  });

  it("treats a single DepGraph the same as an array containing only that graph", () => {
    const graph = buildGraph("npm", "app", [
      { name: "left-pad", version: "1.3.0" },
    ]);

    expect(depGraphsToCycloneDx(graph)).toEqual(depGraphsToCycloneDx([graph]));
  });

  it("omits serialNumber and metadata by default", () => {
    const graph = buildGraph("npm", "app", []);

    const document = depGraphsToCycloneDx(graph);

    expect(document.serialNumber).toBeUndefined();
    expect(document.metadata).toBeUndefined();
  });

  it("includes serialNumber and metadata.timestamp only when provided via options", () => {
    const graph = buildGraph("npm", "app", []);

    const document = depGraphsToCycloneDx(graph, {
      serialNumber: "urn:uuid:1234",
      timestamp: "2024-01-01T00:00:00.000Z",
    });

    expect(document.serialNumber).toBe("urn:uuid:1234");
    expect(document.metadata).toEqual({
      timestamp: "2024-01-01T00:00:00.000Z",
    });
  });
});
