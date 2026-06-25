import { DepGraph, DepGraphBuilder } from "@snyk/dep-graph";
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

const gemfileWithGroups = `source "https://rubygems.org"

gem "rails"
gem "puma", group: :production
gem "debug", group: :development

group :development, :test do
  gem "rspec"
end

group :production do
  gem "pg"
end
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

  it("creates one scan result per directory with a Gemfile.lock", async () => {
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

  it("builds a graph from a Gemfile.lock even without a Gemfile", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile.lock": gemfileLock,
    });

    expect(results).toHaveLength(1);
    expect(results[0].identity).toEqual({
      type: "rubygems",
      targetFile: "/app/Gemfile.lock",
    });
    // No Gemfile present, so only the lockfile is reported as tested.
    expect(results[0].facts).toEqual([
      { type: "depGraph", data: expect.any(Object) },
      { type: "testedFiles", data: ["Gemfile.lock"] },
    ]);

    const depGraph = getDepGraph(results[0]);
    expect(getNodeDeps(depGraph, "root-node")).toEqual([
      "puma@6.4.2",
      "rails@7.0.8",
    ]);
  });

  it("does not scan a directory that only has a Gemfile", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfile,
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

  it("skips an unparseable lockfile that yields no specs but still scans valid ones", async () => {
    const results = await rubyFilesToScannedProjects({
      "/broken/Gemfile": gemfile,
      "/broken/Gemfile.lock": "this is not a lockfile",
      "/app/Gemfile": gemfile,
      "/app/Gemfile.lock": gemfileLock,
    });

    expect(results).toHaveLength(1);
    expect(results[0].identity.targetFile).toBe("/app/Gemfile.lock");
  });

  it("skips a project whose dep-graph construction throws but still scans valid ones", async () => {
    // The "no specs" case above returns null; this exercises the catch path by
    // forcing the graph builder to throw for the first project only.
    const buildSpy = jest
      .spyOn(DepGraphBuilder.prototype, "build")
      .mockImplementationOnce(() => {
        throw new Error("synthetic dep-graph failure");
      });

    try {
      const results = await rubyFilesToScannedProjects({
        "/broken/Gemfile": gemfile,
        "/broken/Gemfile.lock": gemfileLock,
        "/app/Gemfile": gemfile,
        "/app/Gemfile.lock": gemfileLock,
      });

      expect(results).toHaveLength(1);
      expect(results[0].identity.targetFile).toBe("/app/Gemfile.lock");
    } finally {
      buildSpy.mockRestore();
    }
  });

  it("parses path or git dependencies marked with a bang", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

gem "local_tool", git: "https://example.com/local-tool.git"
`,
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

  it("excludes dependencies that are only in development and test groups", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": gemfileWithGroups,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    debug (1.9.2)
    nio4r (2.7.0)
    pg (1.5.6)
    puma (6.4.2)
      nio4r (~> 2.0)
    rails (7.0.8)
    rspec (3.13.0)

PLATFORMS
  ruby

DEPENDENCIES
  debug
  pg
  puma
  rails
  rspec
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(getNodeDeps(depGraph, "root-node")).toEqual([
      "pg@1.5.6",
      "puma@6.4.2",
      "rails@7.0.8",
    ]);
    expect(depGraph.getPkgs()).not.toEqual(
      expect.arrayContaining([
        { name: "debug", version: "1.9.2" },
        { name: "rspec", version: "3.13.0" },
      ]),
    );
  });

  it("returns no scan result when every declared gem is excluded by group", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

group :development, :test do
  gem "debug"
  gem "rspec"
end
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    debug (1.9.2)
    rspec (3.13.0)

PLATFORMS
  ruby

DEPENDENCIES
  debug
  rspec
`,
    });

    expect(results).toHaveLength(0);
  });

  it("keeps multiple locked specs for the same gem name", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

gem "nokogiri"
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.8.7)
    nokogiri (1.18.10)
      mini_portile2 (~> 2.8.2)
    nokogiri (1.18.10-aarch64-linux-gnu)

PLATFORMS
  aarch64-linux-gnu
  ruby

DEPENDENCIES
  nokogiri
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(depGraph.getPkgs()).toEqual(
      expect.arrayContaining([
        { name: "nokogiri", version: "1.18.10" },
        { name: "nokogiri", version: "1.18.10-aarch64-linux-gnu" },
        { name: "mini_portile2", version: "2.8.7" },
      ]),
    );
    expect(getNodeDeps(depGraph, "root-node")).toEqual([
      "nokogiri@1.18.10",
      "nokogiri@1.18.10-aarch64-linux-gnu",
    ]);
  });

  it("does not let a comment containing 'do' corrupt group parsing", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

group :development do
# do not edit the gems below
  gem "rspec"
end

gem "rails"
gem "puma"
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    puma (6.4.2)
    rails (7.0.8)
    rspec (3.13.0)

PLATFORMS
  ruby

DEPENDENCIES
  puma
  rails
  rspec
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    // rails and puma are production gems declared after the group block — they
    // must survive even though a comment inside the block contains "do".
    expect(getNodeDeps(depGraph, "root-node")).toEqual([
      "puma@6.4.2",
      "rails@7.0.8",
    ]);
    expect(depGraph.getPkgs()).not.toEqual(
      expect.arrayContaining([{ name: "rspec", version: "3.13.0" }]),
    );
  });

  it("excludes a gem whose group is set with hash-rocket syntax", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

gem "rails"
gem "byebug", :group => :development
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    byebug (11.1.3)
    rails (7.0.8)

PLATFORMS
  ruby

DEPENDENCIES
  byebug
  rails
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(getNodeDeps(depGraph, "root-node")).toEqual(["rails@7.0.8"]);
  });

  it("excludes a gem whose groups use a %i[] array literal", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

gem "rails"
gem "rspec-rails", groups: %i[development test]
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
    rspec-rails (6.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails
  rspec-rails
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(getNodeDeps(depGraph, "root-node")).toEqual(["rails@7.0.8"]);
  });

  it("excludes a gem whose group is given as a quoted string", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

gem "rails"
gem "byebug", group: "development"
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    byebug (11.1.3)
    rails (7.0.8)

PLATFORMS
  ruby

DEPENDENCIES
  byebug
  rails
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(getNodeDeps(depGraph, "root-node")).toEqual(["rails@7.0.8"]);
  });

  it("applies group filtering across a multi-line gem declaration", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

gem "rails"
gem "rspec",
  "~> 3.13",
  groups: [:development, :test]
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
    rspec (3.13.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails
  rspec
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(getNodeDeps(depGraph, "root-node")).toEqual(["rails@7.0.8"]);
  });

  it("excludes gems inside a group(...) method-call block", async () => {
    const results = await rubyFilesToScannedProjects({
      "/app/Gemfile": `source "https://rubygems.org"

gem "rails"
group(:development) do
  gem "rspec"
end
`,
      "/app/Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
    rspec (3.13.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails
  rspec
`,
    });

    expect(results).toHaveLength(1);
    const depGraph = getDepGraph(results[0]);
    expect(getNodeDeps(depGraph, "root-node")).toEqual(["rails@7.0.8"]);
  });
});
