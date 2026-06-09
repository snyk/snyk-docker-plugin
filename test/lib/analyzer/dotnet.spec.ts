import * as fs from "fs";
import * as path from "path";
import { dotnetFilesToScannedProjects } from "../../../lib/analyzer/applications/dotnet";

const fixturesPath = path.join(__dirname, "../../fixtures/dotnet");

function loadFixture(filename: string): string {
  return fs.readFileSync(path.join(fixturesPath, filename), "utf-8");
}

describe("dotnet deps.json analyzer", () => {
  describe("basic deps.json parsing", () => {
    it("should parse a valid deps.json and produce a scan result", async () => {
      const content = loadFixture("VulnApp.deps.json");
      const filePathToContent = {
        "/app/VulnApp.deps.json": content,
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("nuget");
      expect(results[0].identity.targetFile).toBe("/app/VulnApp.deps.json");
    });

    it("should produce a dep graph with correct root package", async () => {
      const content = loadFixture("VulnApp.deps.json");
      const filePathToContent = {
        "/app/VulnApp.deps.json": content,
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      const depGraphFact = results[0].facts.find((f) => f.type === "depGraph");
      expect(depGraphFact).toBeDefined();

      const depGraph = depGraphFact!.data;
      expect(depGraph.rootPkg.name).toBe("VulnApp");
      expect(depGraph.rootPkg.version).toBe("1.0.0");
    });

    it("should include AutoMapper as a direct dependency", async () => {
      const content = loadFixture("VulnApp.deps.json");
      const filePathToContent = {
        "/app/VulnApp.deps.json": content,
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;

      const pkgs = depGraph.getPkgs();
      const autoMapper = pkgs.find(
        (p) => p.name === "AutoMapper" && p.version === "13.0.1",
      );
      expect(autoMapper).toBeDefined();
    });

    it("should include transitive dependencies", async () => {
      const content = loadFixture("VulnApp.deps.json");
      const filePathToContent = {
        "/app/VulnApp.deps.json": content,
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;

      const pkgs = depGraph.getPkgs();
      const options = pkgs.find(
        (p) => p.name === "Microsoft.Extensions.Options",
      );
      expect(options).toBeDefined();
      expect(options!.version).toBe("6.0.0");

      const primitives = pkgs.find(
        (p) => p.name === "Microsoft.Extensions.Primitives",
      );
      expect(primitives).toBeDefined();
    });

    it("should include testedFiles fact", async () => {
      const content = loadFixture("VulnApp.deps.json");
      const filePathToContent = {
        "/app/VulnApp.deps.json": content,
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      const testedFilesFact = results[0].facts.find(
        (f) => f.type === "testedFiles",
      );
      expect(testedFilesFact).toBeDefined();
      expect(testedFilesFact!.data).toEqual(["VulnApp.deps.json"]);
    });
  });

  describe("self-contained publishes", () => {
    it("should strip the runtimepack. prefix to the canonical NuGet id", async () => {
      const results = await dotnetFilesToScannedProjects({
        "/app/SelfContained.deps.json": loadFixture("SelfContained.deps.json"),
      });
      const pkgs = results[0].facts
        .find((f) => f.type === "depGraph")!
        .data.getPkgs();

      const runtimePack = pkgs.find(
        (p) => p.name === "Microsoft.NETCore.App.Runtime.linux-x64",
      );
      expect(runtimePack).toBeDefined();
      expect(runtimePack!.version).toBe("8.0.27");
      expect(pkgs.some((p) => p.name.startsWith("runtimepack."))).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("should return empty array for non-deps.json files", async () => {
      const filePathToContent = {
        "/app/package.json": '{"name": "test"}',
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(0);
    });

    it("should return empty array for empty input", async () => {
      const results = await dotnetFilesToScannedProjects({});
      expect(results).toHaveLength(0);
    });

    it("should handle invalid JSON gracefully", async () => {
      const filePathToContent = {
        "/app/Broken.deps.json": "not valid json{{{",
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(0);
    });

    it("should handle deps.json with no targets", async () => {
      const filePathToContent = {
        "/app/Empty.deps.json": JSON.stringify({
          runtimeTarget: { name: ".NETCoreApp,Version=v8.0" },
          targets: {},
        }),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(0);
    });

    it("should handle multiple deps.json files", async () => {
      const content = loadFixture("VulnApp.deps.json");
      const frameworkContent = loadFixture("WithFramework.deps.json");
      const filePathToContent = {
        "/app1/VulnApp.deps.json": content,
        "/app2/WithFramework.deps.json": frameworkContent,
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(2);
    });
  });
});
