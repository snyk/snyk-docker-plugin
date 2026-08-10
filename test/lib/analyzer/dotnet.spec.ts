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

  describe("new NuGet manifest/lockfile formats reach the scan pipeline", () => {
    it("parses packages.config into a nuget scan result", async () => {
      const filePathToContent = {
        "/app/packages.config": loadFixture("packages.config"),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("nuget");
      expect(results[0].identity.targetFile).toBe("/app/packages.config");

      const pkgs = results[0].facts
        .find((f) => f.type === "depGraph")!
        .data.getPkgs();
      expect(
        pkgs.some((p) => p.name === "AutoMapper" && p.version === "13.0.1"),
      ).toBe(true);
      expect(pkgs.some((p) => p.name === "DevOnly")).toBe(false);
    });

    it("parses a .csproj into a nuget scan result", async () => {
      const filePathToContent = {
        "/app/VulnApp.csproj": loadFixture("VulnApp.csproj"),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("nuget");

      const pkgs = results[0].facts
        .find((f) => f.type === "depGraph")!
        .data.getPkgs();
      expect(
        pkgs.some((p) => p.name === "AutoMapper" && p.version === "13.0.1"),
      ).toBe(true);
    });

    it("parses packages.lock.json into a nuget scan result with transitive deps", async () => {
      const filePathToContent = {
        "/app/packages.lock.json": loadFixture("packages.lock.json"),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("nuget");

      const pkgs = results[0].facts
        .find((f) => f.type === "depGraph")!
        .data.getPkgs();
      expect(
        pkgs.some((p) => p.name === "AutoMapper" && p.version === "13.0.1"),
      ).toBe(true);
      expect(
        pkgs.some(
          (p) =>
            p.name === "Microsoft.Extensions.DependencyInjection.Abstractions",
        ),
      ).toBe(true);
    });

    it("parses obj/project.assets.json into a nuget scan result", async () => {
      const filePathToContent = {
        "/app/obj/project.assets.json": loadFixture("project.assets.json"),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("nuget");
      expect(results[0].identity.targetFile).toBe(
        "/app/obj/project.assets.json",
      );

      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      expect(depGraph.rootPkg.name).toBe("VulnApp");
      const pkgs = depGraph.getPkgs();
      expect(
        pkgs.some((p) => p.name === "AutoMapper" && p.version === "13.0.1"),
      ).toBe(true);
    });

    it("prefers project.assets.json over packages.lock.json, packages.config, and a project file in the same root", async () => {
      const filePathToContent = {
        "/app/obj/project.assets.json": loadFixture("project.assets.json"),
        "/app/packages.lock.json": loadFixture("packages.lock.json"),
        "/app/packages.config": loadFixture("packages.config"),
        "/app/VulnApp.csproj": loadFixture("VulnApp.csproj"),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.targetFile).toBe(
        "/app/obj/project.assets.json",
      );
    });

    it("suppresses the new-format result when a deps.json exists under the same project root", async () => {
      const filePathToContent = {
        "/app/VulnApp.csproj": loadFixture("VulnApp.csproj"),
        "/app/bin/publish/VulnApp.deps.json": loadFixture("VulnApp.deps.json"),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.targetFile).toBe(
        "/app/bin/publish/VulnApp.deps.json",
      );
    });

    it("does not suppress a new-format result when deps.json belongs to an unrelated root", async () => {
      const filePathToContent = {
        "/app1/VulnApp.csproj": loadFixture("VulnApp.csproj"),
        "/app2/VulnApp.deps.json": loadFixture("VulnApp.deps.json"),
      };

      const results = await dotnetFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(2);
      const targetFiles = results.map((r) => r.identity.targetFile).sort();
      expect(targetFiles).toEqual([
        "/app1/VulnApp.csproj",
        "/app2/VulnApp.deps.json",
      ]);
    });
  });
});
