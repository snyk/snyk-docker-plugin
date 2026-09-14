import { DepGraph } from "@snyk/dep-graph";
import { readFileSync } from "fs";
import { uvFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { AppDepsScanResultWithoutTarget } from "../../../lib/analyzer/applications/types";
import { getFixture } from "../../util";

function realUvLock(): string {
  return readFileSync(getFixture("python/uv/uv.lock"), "utf8");
}

function getDepGraph(result: AppDepsScanResultWithoutTarget): DepGraph {
  return result.facts.find((fact) => fact.type === "depGraph")!.data;
}

function getNodeDeps(depGraph: DepGraph, nodeId: string): string[] {
  const node = depGraph
    .toJSON()
    .graph.nodes.find((graphNode) => graphNode.nodeId === nodeId);
  return node ? node.deps.map((dep) => dep.nodeId).sort() : [];
}

function pkgKeys(depGraph: DepGraph): string[] {
  return depGraph
    .getDepPkgs()
    .map((pkg) => `${pkg.name}@${pkg.version}`)
    .sort();
}

describe("uv analyzer", () => {
  it("emits the expected scan-result contract for a uv.lock", async () => {
    const results = await uvFilesToScannedProjects({
      "/app/uv.lock": realUvLock(),
    });

    expect(results).toHaveLength(1);
    expect(results[0].identity).toEqual({
      type: "uv",
      targetFile: "/app/uv.lock",
    });
    expect(results[0].facts).toEqual([
      { type: "depGraph", data: expect.any(Object) },
      { type: "testedFiles", data: ["uv.lock"] },
    ]);

    const depGraph = getDepGraph(results[0]);
    expect(depGraph.pkgManager.name).toBe("uv");
    expect(depGraph.rootPkg.name).toBe("sample-uv-app");
    expect(depGraph.rootPkg.version).toBe("1.2.3");
  });

  it("builds the production graph with direct and transitive deps", async () => {
    const results = await uvFilesToScannedProjects({
      "/app/uv.lock": realUvLock(),
    });
    const depGraph = getDepGraph(results[0]);

    // Root's direct production deps come from the editable package's
    // `dependencies` table (flask + requests).
    expect(getNodeDeps(depGraph, "root-node")).toEqual([
      "flask@3.0.3",
      "requests@2.32.3",
    ]);

    // Transitive resolution follows each package's own dependencies, with
    // versions resolved from the locked packages (not the requirement spec).
    expect(getNodeDeps(depGraph, "flask@3.0.3")).toEqual([
      "blinker@1.9.0",
      "click@8.4.2",
      "itsdangerous@2.2.0",
      "jinja2@3.1.6",
      "werkzeug@3.1.8",
    ]);
    expect(getNodeDeps(depGraph, "requests@2.32.3")).toEqual([
      "certifi@2026.6.17",
      "charset-normalizer@3.4.7",
      "idna@3.18",
      "urllib3@2.7.0",
    ]);

    // markupsafe is a shared transitive (via jinja2 and werkzeug) and should be
    // a single deduped node.
    expect(getNodeDeps(depGraph, "jinja2@3.1.6")).toEqual(["markupsafe@3.0.3"]);
    expect(getNodeDeps(depGraph, "werkzeug@3.1.8")).toEqual([
      "markupsafe@3.0.3",
    ]);

    // colorama is only reachable through click (a production dep). Even though
    // its edge carries a win32 marker, uv.lock is a universal lockfile so we
    // keep it.
    expect(getNodeDeps(depGraph, "click@8.4.2")).toEqual(["colorama@0.4.6"]);
  });

  it("excludes dev/group dependencies", async () => {
    const results = await uvFilesToScannedProjects({
      "/app/uv.lock": realUvLock(),
    });
    const keys = pkgKeys(getDepGraph(results[0]));

    // pytest and the packages reachable only through it must not appear.
    expect(keys).not.toContain("pytest@8.3.3");
    expect(keys).not.toContain("iniconfig@2.3.0");
    expect(keys).not.toContain("pluggy@1.6.0");
    expect(keys).not.toContain("packaging@26.2");

    // 18 resolved packages minus the root minus the 4 dev-only packages.
    expect(keys).toHaveLength(13);
  });

  it("creates one scan result per uv.lock", async () => {
    const lock = realUvLock();
    const results = await uvFilesToScannedProjects({
      "/app/uv.lock": lock,
      "/service/uv.lock": lock,
    });

    expect(results.map((result) => result.identity.targetFile).sort()).toEqual([
      "/app/uv.lock",
      "/service/uv.lock",
    ]);
  });

  it("detects a virtual workspace root", async () => {
    const lock = `version = 1

[[package]]
name = "workspace-root"
version = "0.0.0"
source = { virtual = "." }
dependencies = [
    { name = "attrs" },
]

[[package]]
name = "attrs"
version = "24.2.0"
source = { registry = "https://pypi.org/simple" }
`;
    const results = await uvFilesToScannedProjects({ "/app/uv.lock": lock });

    expect(results).toHaveLength(1);
    expect(getDepGraph(results[0]).rootPkg.name).toBe("workspace-root");
    expect(pkgKeys(getDepGraph(results[0]))).toEqual(["attrs@24.2.0"]);
  });

  it("connects to every locked version when a name resolves to several", async () => {
    const lock = `version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "lib-a" },
    { name = "lib-b" },
]

[[package]]
name = "lib-a"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "shared" },
]

[[package]]
name = "lib-b"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "shared" },
]

[[package]]
name = "shared"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "shared"
version = "2.5.0"
source = { registry = "https://pypi.org/simple" }
`;
    const results = await uvFilesToScannedProjects({ "/app/uv.lock": lock });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(pkgKeys(depGraph)).toEqual([
      "lib-a@1.0.0",
      "lib-b@2.0.0",
      "shared@1.5.0",
      "shared@2.5.0",
    ]);
    expect(getNodeDeps(depGraph, "lib-a@1.0.0")).toEqual([
      "shared@1.5.0",
      "shared@2.5.0",
    ]);
  });

  it("skips a malformed lockfile but still scans valid ones", async () => {
    const results = await uvFilesToScannedProjects({
      "/broken/uv.lock": "this is = not valid : toml [[",
      "/app/uv.lock": realUvLock(),
    });

    expect(results).toHaveLength(1);
    expect(results[0].identity.targetFile).toBe("/app/uv.lock");
  });

  it("returns no result when the lockfile has no packages", async () => {
    const results = await uvFilesToScannedProjects({
      "/app/uv.lock": `version = 1\nrequires-python = ">=3.11"\n`,
    });

    expect(results).toHaveLength(0);
  });

  it("returns no result when the root project is ambiguous", async () => {
    // Two editable roots and nothing depends on either, so neither the marker
    // nor the sink heuristic can pick a single root.
    const lock = `version = 1

[[package]]
name = "member-a"
version = "0.1.0"
source = { editable = "packages/a" }

[[package]]
name = "member-b"
version = "0.1.0"
source = { editable = "packages/b" }
`;
    const results = await uvFilesToScannedProjects({ "/app/uv.lock": lock });

    expect(results).toHaveLength(0);
  });

  it("ignores files that are not named uv.lock", async () => {
    const results = await uvFilesToScannedProjects({
      "/app/pyproject.toml": "[project]\nname = 'x'\n",
    });

    expect(results).toHaveLength(0);
  });
});
