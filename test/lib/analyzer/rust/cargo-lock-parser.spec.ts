import * as fs from "fs";
import * as path from "path";
import {
  parseCargoLock,
  parseDependencyString,
} from "../../../../lib/analyzer/applications/rust/cargo-lock-parser";

const fixturesPath = path.join(__dirname, "../../../fixtures/rust");

function loadFixture(relativePath: string): string {
  return fs.readFileSync(path.join(fixturesPath, relativePath), "utf-8");
}

describe("parseDependencyString", () => {
  it("parses bare crate name", () => {
    expect(parseDependencyString("serde")).toEqual({ name: "serde" });
  });

  it("parses name and version", () => {
    expect(parseDependencyString("serde 1.0.0")).toEqual({
      name: "serde",
      version: "1.0.0",
    });
  });

  it("parses lock v2/v3/v4 name version source", () => {
    expect(
      parseDependencyString(
        "serde 1.0.0 registry+https://github.com/rust-lang/crates.io-index",
      ),
    ).toEqual({ name: "serde", version: "1.0.0" });
  });

  it("parses lock v1 name version (source)", () => {
    expect(
      parseDependencyString(
        "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
      ),
    ).toEqual({ name: "serde", version: "1.0.0" });
  });
});

describe("parseCargoLock", () => {
  it("ignores the generated header comment and top-level version key", () => {
    const content = loadFixture("simple/Cargo.lock");
    const packages = parseCargoLock(content);
    expect(packages.length).toBeGreaterThan(0);
    expect(packages.every((p) => p.name !== "3")).toBe(true);
  });

  it("parses multi-line dependencies arrays", () => {
    const content = loadFixture("simple/Cargo.lock");
    const myApp = parseCargoLock(content).find((p) => p.name === "my-app");
    expect(myApp).toBeDefined();
    expect(myApp!.dependencies).toEqual(
      expect.arrayContaining([
        { name: "serde", version: "1.0.193" },
        { name: "serde_json", version: "1.0.108" },
      ]),
    );
  });

  it("parses inline dependencies arrays", () => {
    const content = `[[package]]
name = "inline-deps"
version = "1.0.0"
dependencies = ["a", "b 1.0.0"]`;
    const packages = parseCargoLock(content);
    expect(packages).toHaveLength(1);
    expect(packages[0].dependencies).toEqual([
      { name: "a" },
      { name: "b", version: "1.0.0" },
    ]);
  });

  it("resolves all four dependency string forms in v1-legacy fixture", () => {
    const content = loadFixture("v1-legacy/Cargo.lock");
    const packages = parseCargoLock(content);
    const legacyApp = packages.find((p) => p.name === "legacy-app");
    expect(legacyApp).toBeDefined();
    expect(legacyApp!.dependencies).toEqual(
      expect.arrayContaining([
        { name: "serde", version: "1.0.0" },
        { name: "bare-crate" },
      ]),
    );
  });

  it("does not include metadata or patch tables as packages", () => {
    const content = loadFixture("v1-legacy/Cargo.lock");
    const packages = parseCargoLock(content);
    expect(packages.find((p) => p.name === "ignored-patch")).toBeUndefined();
    expect(packages).toHaveLength(3);
  });

  it("returns undefined source when source key is absent", () => {
    const content = loadFixture("simple/Cargo.lock");
    const myApp = parseCargoLock(content).find((p) => p.name === "my-app");
    expect(myApp).toBeDefined();
    expect(myApp!.source).toBeUndefined();
  });

  it("returns empty array for malformed input", () => {
    expect(parseCargoLock("not valid toml {{{")).toEqual([]);
  });

  it("returns empty array for empty input", () => {
    expect(parseCargoLock("")).toEqual([]);
    expect(parseCargoLock("   ")).toEqual([]);
  });

  it("parses workspace fixture packages", () => {
    const content = loadFixture("workspace/Cargo.lock");
    const packages = parseCargoLock(content);
    expect(packages.map((p) => p.name).sort()).toEqual([
      "member-a",
      "member-b",
      "serde",
    ]);
  });

  it("parses cyclic fixture without error", () => {
    const content = loadFixture("cyclic/Cargo.lock");
    const packages = parseCargoLock(content);
    expect(packages).toHaveLength(3);
  });
});
