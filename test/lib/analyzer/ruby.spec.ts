import { DepGraph } from "@snyk/dep-graph";
import { rubyFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { AppDepsScanResultWithoutTarget } from "../../../lib/analyzer/applications/types";

const gemfile = `source "https://rubygems.org"

gem "rails"
gem "puma"
`;

const gemfileLock = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.8)
      rack (~> 2.0)
    activesupport (7.0.8)
      minitest (>= 5.1)
    minitest (5.20.0)
    nio4r (2.7.0)
    puma (6.4.2)
      nio4r (~> 2.0)
    rack (2.2.8)
    rails (7.0.8)
      actionpack (= 7.0.8)
      activesupport (= 7.0.8)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0.0)
  puma (~> 6.0)

BUNDLED WITH
   2.5.6
`;

function getDepGraph(result: AppDepsScanResultWithoutTarget): DepGraph {
  return result.facts.find((fact) => fact.type === "depGraph")!.data;
}

function getNodeDeps(depGraph: DepGraph, nodeId: string): string[] {
  const node = depGraph
    .toJSON()
    .graph.nodes.find((graphNode) => graphNode.nodeId === nodeId);
  return node ? node.deps.map((dep) => dep.nodeId).sort() : [];
}

describe("ruby Gemfile.lock analyzer", () => {
  it("creates a rubygems scan result from Gemfile and Gemfile.lock", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfile,
      "/app/Gemfile.lock": gemfileLock,
    });

    expect(results).toHaveLength(1);
    expect(results[0].identity).toEqual({
      type: "rubygems",
      targetFile: "/app/Gemfile.lock",
    });
    expect(results[0].facts).toEqual([
      { type: "depGraph", data: expect.any(Object) },
      { type: "testedFiles", data: ["Gemfile", "Gemfile.lock"] },
    ]);
  });

  it("builds direct and transitive dependencies from the lockfile", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfile,
      "/app/Gemfile.lock": gemfileLock,
    });

    const depGraph = getDepGraph(results[0]);
    expect(depGraph.pkgManager.name).toBe("rubygems");
    expect(depGraph.rootPkg.name).toBe("/app/Gemfile.lock");
    expect(depGraph.getPkgs()).toEqual(
      expect.arrayContaining([
        { name: "rails", version: "7.0.8" },
        { name: "puma", version: "6.4.2" },
        { name: "actionpack", version: "7.0.8" },
        { name: "rack", version: "2.2.8" },
        { name: "activesupport", version: "7.0.8" },
        { name: "minitest", version: "5.20.0" },
        { name: "nio4r", version: "2.7.0" },
      ]),
    );
    expect(getNodeDeps(depGraph, "root-node")).toEqual([
      "puma@6.4.2",
      "rails@7.0.8",
    ]);
    expect(getNodeDeps(depGraph, "rails@7.0.8")).toEqual([
      "actionpack@7.0.8",
      "activesupport@7.0.8",
    ]);
    expect(getNodeDeps(depGraph, "actionpack@7.0.8")).toEqual(["rack@2.2.8"]);
  });

  it("creates one scan result per directory with a complete manifest pair", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfile,
      "/app/Gemfile.lock": gemfileLock,
      "/worker/Gemfile": gemfile,
      "/worker/Gemfile.lock": gemfileLock,
    });

    expect(results).toHaveLength(2);
    expect(results.map((result) => result.identity.targetFile).sort()).toEqual([
      "/app/Gemfile.lock",
      "/worker/Gemfile.lock",
    ]);
  });

  it("ignores files unless Gemfile and Gemfile.lock are in the same directory", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfile,
      "/worker/Gemfile.lock": gemfileLock,
    });

    expect(results).toHaveLength(0);
  });

  it("ignores a lockfile that has no resolved specs", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfile,
      "/app/Gemfile.lock": `DEPENDENCIES
  rails
`,
    });

    expect(results).toHaveLength(0);
  });

  it("parses path or git dependencies marked with a bang", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfile,
      "/app/Gemfile.lock": `GIT
  remote: https://example.com/local-tool.git
  revision: abc123
  specs:
    local_tool (0.1.0)
      thor (>= 1.0)

GEM
  remote: https://rubygems.org/
  specs:
    thor (1.3.0)

PLATFORMS
  ruby

DEPENDENCIES
  local_tool!
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(depGraph.getPkgs()).toEqual(
      expect.arrayContaining([
        { name: "local_tool", version: "0.1.0" },
        { name: "thor", version: "1.3.0" },
      ]),
    );
    expect(getNodeDeps(depGraph, "local_tool@0.1.0")).toEqual(["thor@1.3.0"]);
  });
});
