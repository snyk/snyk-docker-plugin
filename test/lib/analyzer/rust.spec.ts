import * as fs from "fs";
import * as path from "path";
import {
  buildDepGraphFromCargoLock,
  parseCargoLock,
  rustFilesToScannedProjects,
} from "../../../lib/analyzer/applications/rust";

const fixturesPath = path.join(__dirname, "../../fixtures/rust");

function loadFixture(filename: string): string {
  return fs.readFileSync(path.join(fixturesPath, filename), "utf-8");
}

describe("Cargo.lock parsing", () => {
  it("should parse [[package]] blocks into name/version/source/dependencies", () => {
    const content = loadFixture("Simple.Cargo.lock");
    const packages = parseCargoLock(content);

    expect(packages).toHaveLength(3);

    const root = packages.find((p) => p.name === "simple-app");
    expect(root).toBeDefined();
    expect(root!.version).toBe("0.1.0");
    expect(root!.source).toBeUndefined();
    expect(root!.dependencies).toEqual(["libc", "log"]);

    const libc = packages.find((p) => p.name === "libc");
    expect(libc).toBeDefined();
    expect(libc!.source).toContain("registry+");
  });
});

describe("rust Cargo.lock analyzer", () => {
  describe("basic Cargo.lock parsing", () => {
    it("should produce a scan result with identity type cargo", async () => {
      const content = loadFixture("Simple.Cargo.lock");
      const filePathToContent = { "/app/Cargo.lock": content };

      const results = await rustFilesToScannedProjects(filePathToContent);

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("cargo");
      expect(results[0].identity.targetFile).toBe("/app/Cargo.lock");
    });

    it("should produce a dep graph with correct root package and direct deps", async () => {
      const content = loadFixture("Simple.Cargo.lock");
      const filePathToContent = { "/app/Cargo.lock": content };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find((f) => f.type === "depGraph")!
        .data;

      expect(depGraph.rootPkg.name).toBe("simple-app");
      expect(depGraph.rootPkg.version).toBe("0.1.0");

      const pkgs = depGraph.getPkgs();
      expect(pkgs.some((p) => p.name === "libc" && p.version === "0.2.150")).toBe(
        true,
      );
      expect(pkgs.some((p) => p.name === "log" && p.version === "0.4.20")).toBe(
        true,
      );
    });

    it("should include testedFiles fact", async () => {
      const content = loadFixture("Simple.Cargo.lock");
      const filePathToContent = { "/app/Cargo.lock": content };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const testedFilesFact = results[0].facts.find(
        (f) => f.type === "testedFiles",
      );
      expect(testedFilesFact).toBeDefined();
      expect(testedFilesFact!.data).toEqual(["Cargo.lock"]);
    });

    it("should ignore standalone Cargo.toml files with no adjacent lock file", async () => {
      const filePathToContent = {
        "/app/Cargo.toml": '[package]\nname = "no-lock"\n',
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(0);
    });
  });

  describe("transitive dependencies", () => {
    it("should include a transitive dependency, connected via the direct dep", async () => {
      const content = loadFixture("WithTransitive.Cargo.lock");
      const filePathToContent = { "/app/Cargo.lock": content };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find((f) => f.type === "depGraph")!
        .data;

      const pkgs = depGraph.getPkgs();
      expect(pkgs.some((p) => p.name === "reqwest")).toBe(true);
      const mime = pkgs.find((p) => p.name === "mime");
      expect(mime).toBeDefined();
      expect(mime!.version).toBe("0.3.17");

      const reqwestDeps = depGraph
        .getDepPkgs()
        .filter((p) => p.name === "mime");
      expect(reqwestDeps).toHaveLength(1);
    });
  });

  describe("duplicate crate versions", () => {
    it("should resolve a versioned dependency reference to the matching version", async () => {
      const content = loadFixture("DuplicateVersions.Cargo.lock");
      const filePathToContent = { "/app/Cargo.lock": content };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find((f) => f.type === "depGraph")!
        .data;

      const pkgs = depGraph.getPkgs();
      const randPkgs = pkgs.filter((p) => p.name === "rand");
      // Both versions exist in the lock file's package list overall, but
      // only the disambiguated "rand 0.8.5" dependency edge should be
      // reachable from the root.
      expect(randPkgs.some((p) => p.version === "0.8.5")).toBe(true);

      const depPkgs = depGraph.getDepPkgs();
      expect(depPkgs.some((p) => p.name === "rand" && p.version === "0.8.5")).toBe(
        true,
      );
      expect(
        depPkgs.some((p) => p.name === "rand" && p.version === "0.7.3"),
      ).toBe(false);
    });
  });

  describe("workspaces", () => {
    it("should synthesize a virtual root depending on each local member", async () => {
      const content = loadFixture("Workspace.Cargo.lock");
      const filePathToContent = {
        "/repo/my-workspace/Cargo.lock": content,
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      const depGraph = results[0].facts.find((f) => f.type === "depGraph")!
        .data;

      expect(depGraph.rootPkg.name).toBe("my-workspace");
      expect(depGraph.rootPkg.version).toBe("0.0.0");

      const depPkgs = depGraph.getDepPkgs();
      expect(depPkgs.some((p) => p.name === "workspace-cli")).toBe(true);
      expect(depPkgs.some((p) => p.name === "workspace-core")).toBe(true);
      expect(depPkgs.some((p) => p.name === "serde")).toBe(true);
    });
  });

  describe("edge cases", () => {
    it("should return empty array for a malformed Cargo.lock (missing version fields)", async () => {
      const content = loadFixture("Malformed.Cargo.lock");
      const filePathToContent = { "/app/Cargo.lock": content };

      const results = await rustFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(0);
    });

    it("should return empty array for empty input", async () => {
      const results = await rustFilesToScannedProjects({});
      expect(results).toHaveLength(0);
    });

    it("should return null from buildDepGraphFromCargoLock when there are no local packages", async () => {
      const content = `
[[package]]
name = "only-external"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`;
      const depGraph = await buildDepGraphFromCargoLock(
        content,
        "/app/Cargo.lock",
      );
      expect(depGraph).toBeNull();
    });

    it("should handle multiple Cargo.lock files", async () => {
      const content = loadFixture("Simple.Cargo.lock");
      const transitiveContent = loadFixture("WithTransitive.Cargo.lock");
      const filePathToContent = {
        "/app1/Cargo.lock": content,
        "/app2/Cargo.lock": transitiveContent,
      };

      const results = await rustFilesToScannedProjects(filePathToContent);
      expect(results).toHaveLength(2);
    });
  });
});
