import * as fs from "fs";
import * as path from "path";
import { rustFilesToScannedProjects } from "../../../../lib/analyzer/applications/rust";

const fixturesPath = path.join(__dirname, "../../../fixtures/rust");

function loadFixture(relativePath: string): string {
  return fs.readFileSync(path.join(fixturesPath, relativePath), "utf-8");
}

describe("rust Cargo.lock analyzer", () => {
  describe("simple fixture", () => {
    const lockPath = "/app/simple/Cargo.lock";
    const manifestPath = "/app/simple/Cargo.toml";

    it("produces one result with cargo identity and full lockfile path", async () => {
      const filePathToContent = {
        [lockPath]: loadFixture("simple/Cargo.lock"),
        [manifestPath]: loadFixture("simple/Cargo.toml"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("cargo");
      expect(results[0].identity.targetFile).toBe(lockPath);
    });

    it("records both tested files when manifest is present", async () => {
      const filePathToContent = {
        [lockPath]: loadFixture("simple/Cargo.lock"),
        [manifestPath]: loadFixture("simple/Cargo.toml"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const testedFiles = results[0].facts.find(
        (f) => f.type === "testedFiles",
      );

      expect(testedFiles!.data).toEqual(["Cargo.toml", "Cargo.lock"]);
    });

    it("uses Cargo.toml [package] name and version as dep graph root", async () => {
      const filePathToContent = {
        [lockPath]: loadFixture("simple/Cargo.lock"),
        [manifestPath]: loadFixture("simple/Cargo.toml"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;

      expect(depGraph.rootPkg.name).toBe("my-app");
      expect(depGraph.rootPkg.version).toBe("0.1.0");
    });

    it("includes transitive dependencies and preserves hyphenated crate names", async () => {
      const filePathToContent = {
        [lockPath]: loadFixture("simple/Cargo.lock"),
        [manifestPath]: loadFixture("simple/Cargo.toml"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      const pkgs = depGraph.getPkgs();

      expect(
        pkgs.find((p) => p.name === "serde_json" && p.version === "1.0.108"),
      ).toBeDefined();
      expect(
        pkgs.find((p) => p.name === "serde" && p.version === "1.0.193"),
      ).toBeDefined();
      expect(pkgs.some((p) => p.name.includes("_"))).toBe(true);
    });

    it("falls back to the single source-less package when no manifest is present", async () => {
      const filePathToContent = {
        [lockPath]: loadFixture("simple/Cargo.lock"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      const testedFiles = results[0].facts.find(
        (f) => f.type === "testedFiles",
      );

      expect(depGraph.rootPkg.name).toBe("my-app");
      expect(depGraph.rootPkg.version).toBe("0.1.0");
      expect(testedFiles!.data).toEqual(["Cargo.lock"]);
    });
  });

  describe("workspace fixture", () => {
    const lockPath = "/app/workspace/Cargo.lock";
    const manifestPath = "/app/workspace/Cargo.toml";

    it("uses directory basename as root with all members as direct deps", async () => {
      const filePathToContent = {
        [lockPath]: loadFixture("workspace/Cargo.lock"),
        [manifestPath]: loadFixture("workspace/Cargo.toml"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;

      expect(results).toHaveLength(1);
      expect(depGraph.rootPkg.name).toBe("workspace");
      expect(depGraph.rootPkg.version).toBe("0.0.0");

      const pkgs = depGraph.getPkgs();
      expect(
        pkgs.find((p) => p.name === "member-a" && p.version === "0.1.0"),
      ).toBeDefined();
      expect(
        pkgs.find((p) => p.name === "member-b" && p.version === "0.2.0"),
      ).toBeDefined();
    });
  });

  describe("multiple lockfiles", () => {
    it("yields one result per Cargo.lock in different directories", async () => {
      const filePathToContent = {
        "/app/a/Cargo.lock": loadFixture("simple/Cargo.lock"),
        "/app/b/Cargo.lock": loadFixture("cyclic/Cargo.lock"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(2);
      expect(results.map((r) => r.identity.targetFile).sort()).toEqual([
        "/app/a/Cargo.lock",
        "/app/b/Cargo.lock",
      ]);
    });
  });

  describe("cyclic fixture", () => {
    it("builds a dep graph without hanging or throwing", async () => {
      const filePathToContent = {
        "/app/cyclic/Cargo.lock": loadFixture("cyclic/Cargo.lock"),
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(1);
      expect(
        results[0].facts.find((f) => f.type === "depGraph")!.data.getPkgs()
          .length,
      ).toBeGreaterThan(0);
    });
  });

  describe("edge cases", () => {
    it("returns zero results for manifest-only directory", async () => {
      const results = await rustFilesToScannedProjects({
        "/app/Cargo.toml": loadFixture("simple/Cargo.toml"),
      });
      expect(results).toHaveLength(0);
    });

    it("returns zero results for empty input", async () => {
      const results = await rustFilesToScannedProjects({});
      expect(results).toHaveLength(0);
    });

    it("returns zero results for malformed lockfile", async () => {
      const results = await rustFilesToScannedProjects({
        "/app/Cargo.lock": "not a valid lockfile {{{",
      });
      expect(results).toHaveLength(0);
    });
  });
});
