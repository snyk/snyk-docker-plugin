import * as fs from "fs";
import * as path from "path";
import { cargoFilesToScannedProjects } from "../../../lib/analyzer/applications/rust";

const fixturesPath = path.join(__dirname, "../../fixtures/rust");

function loadFixture(relativePath: string): string {
  return fs.readFileSync(path.join(fixturesPath, relativePath), "utf-8");
}

describe("cargoFilesToScannedProjects", () => {
  it("parses Cargo.lock with adjacent Cargo.toml into one cargo scan result", async () => {
    const filePathToContent = {
      "/app/Cargo.lock": loadFixture("app/Cargo.lock"),
      "/app/Cargo.toml": loadFixture("app/Cargo.toml"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);

    expect(results).toHaveLength(1);
    expect(results[0].identity.type).toBe("cargo");
    expect(results[0].identity.targetFile).toBe("/app/Cargo.lock");
  });

  it("builds dep graph with root from Cargo.toml package name", async () => {
    const filePathToContent = {
      "/app/Cargo.lock": loadFixture("app/Cargo.lock"),
      "/app/Cargo.toml": loadFixture("app/Cargo.toml"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);
    const depGraph = results[0].facts.find((f) => f.type === "depGraph")!.data;

    expect(depGraph.rootPkg.name).toBe("my-rust-app");
  });

  it("includes direct and transitive crate dependencies at correct versions", async () => {
    const filePathToContent = {
      "/app/Cargo.lock": loadFixture("app/Cargo.lock"),
      "/app/Cargo.toml": loadFixture("app/Cargo.toml"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);
    const depGraph = results[0].facts.find((f) => f.type === "depGraph")!.data;
    const pkgs = depGraph.getPkgs();

    const serde = pkgs.find(
      (p) => p.name === "serde" && p.version === "1.0.130",
    );
    expect(serde).toBeDefined();

    const pinProjectLite = pkgs.find(
      (p) => p.name === "pin-project-lite" && p.version === "0.2.0",
    );
    expect(pinProjectLite).toBeDefined();
  });

  it("includes testedFiles fact with both manifest and lockfile", async () => {
    const filePathToContent = {
      "/app/Cargo.lock": loadFixture("app/Cargo.lock"),
      "/app/Cargo.toml": loadFixture("app/Cargo.toml"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);
    const testedFiles = results[0].facts.find(
      (f) => f.type === "testedFiles",
    )!.data;

    expect(testedFiles).toEqual(["Cargo.lock", "Cargo.toml"]);
  });

  it("handles Cargo.lock without adjacent Cargo.toml with derived root", async () => {
    const filePathToContent = {
      "/app/Cargo.lock": loadFixture("no-manifest/Cargo.lock"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);

    expect(results).toHaveLength(1);
    expect(results[0].identity.type).toBe("cargo");
    const depGraph = results[0].facts.find((f) => f.type === "depGraph")!.data;
    expect(depGraph.rootPkg.name).toBe("standalone-crate");

    const testedFiles = results[0].facts.find(
      (f) => f.type === "testedFiles",
    )!.data;
    expect(testedFiles).toEqual(["Cargo.lock"]);
  });

  it("handles cyclic lockfiles without stack overflow", async () => {
    const filePathToContent = {
      "/app/Cargo.lock": loadFixture("cyclic/Cargo.lock"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);

    expect(results).toHaveLength(1);
    const depGraph = results[0].facts.find((f) => f.type === "depGraph")!.data;
    expect(depGraph.getPkgs().length).toBeGreaterThan(0);
  });

  it("returns empty array for malformed lockfile content without throwing", async () => {
    const filePathToContent = {
      "/app/Cargo.lock": loadFixture("lockfile-formats/malformed.Cargo.lock"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);
    expect(results).toEqual([]);
  });

  it("returns empty array for empty input without throwing", async () => {
    const results = await cargoFilesToScannedProjects({});
    expect(results).toEqual([]);
  });

  it("returns two results for two Cargo.lock files in different directories", async () => {
    const filePathToContent = {
      "/app1/Cargo.lock": loadFixture("app/Cargo.lock"),
      "/app1/Cargo.toml": loadFixture("app/Cargo.toml"),
      "/app2/Cargo.lock": loadFixture("no-manifest/Cargo.lock"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);
    expect(results).toHaveLength(2);
  });

  it("produces no scan result for Cargo.toml without adjacent Cargo.lock", async () => {
    const filePathToContent = {
      "/app/Cargo.toml": loadFixture("app/Cargo.toml"),
    };

    const results = await cargoFilesToScannedProjects(filePathToContent);
    expect(results).toEqual([]);
  });
});
