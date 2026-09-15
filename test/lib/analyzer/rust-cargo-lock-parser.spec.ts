import * as fs from "fs";
import * as path from "path";
import {
  CargoLockParseError,
  parseCargoLock,
  parseDependencyRef,
  resolveDependencyPackage,
} from "../../../lib/analyzer/applications/rust/cargo-lock-parser";

const fixturesPath = path.join(
  __dirname,
  "../../fixtures/rust/lockfile-formats",
);

function loadFixture(filename: string): string {
  return fs.readFileSync(path.join(fixturesPath, filename), "utf-8");
}

describe("parseCargoLock", () => {
  it("parses v1 lockfile with metadata checksums and full dependency encoding", () => {
    const result = parseCargoLock(loadFixture("v1.Cargo.lock"));

    expect(result.lockfileVersion).toBe(1);
    expect(result.packages).toHaveLength(3);

    const app = result.packages.find((p) => p.name === "v1-app");
    expect(app).toBeDefined();
    expect(app!.version).toBe("0.1.0");
    expect(app!.dependencies).toEqual([
      "serde 1.0.130 (registry+https://github.com/rust-lang/crates.io-index)",
      "libc 0.2.147 (registry+https://github.com/rust-lang/crates.io-index)",
    ]);

    const serde = result.packages.find((p) => p.name === "serde");
    expect(serde!.source).toBe(
      "registry+https://github.com/rust-lang/crates.io-index",
    );
  });

  it("parses v2 lockfile with inline checksums and compact dependencies", () => {
    const result = parseCargoLock(loadFixture("v2.Cargo.lock"));

    expect(result.lockfileVersion).toBe(1);
    expect(result.packages).toHaveLength(3);

    const app = result.packages.find((p) => p.name === "v2-app");
    expect(app!.dependencies).toEqual(["serde", "bitflags 2.4.0"]);
  });

  it("parses v3 lockfile with version field and git branch encoding", () => {
    const result = parseCargoLock(loadFixture("v3.Cargo.lock"));

    expect(result.lockfileVersion).toBe(3);
    expect(result.packages).toHaveLength(2);

    const gitDep = result.packages.find((p) => p.name === "git-dep");
    expect(gitDep!.source).toBe(
      "git+https://github.com/example/repo?branch=master#abc123def456",
    );
  });

  it("parses v4 lockfile with URL-encoded branch names", () => {
    const result = parseCargoLock(loadFixture("v4.Cargo.lock"));

    expect(result.lockfileVersion).toBe(4);
    expect(result.packages).toHaveLength(2);

    const encodedDep = result.packages.find((p) => p.name === "encoded-dep");
    expect(encodedDep!.source).toBe(
      "git+https://github.com/example/repo?branch=foo+bar#abc123def456",
    );
  });

  it("throws CargoLockParseError for malformed lockfile content", () => {
    expect(() => parseCargoLock(loadFixture("malformed.Cargo.lock"))).toThrow(
      CargoLockParseError,
    );
  });

  it("throws CargoLockParseError for empty content", () => {
    expect(() => parseCargoLock("")).toThrow(CargoLockParseError);
    expect(() => parseCargoLock("   ")).toThrow(CargoLockParseError);
  });

  it("excludes [[patch.unused]] entries from packages", () => {
    const content = `
version = 3

[[package]]
name = "real-app"
version = "0.1.0"

[[patch.unused]]
name = "patched-crate"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "some-dep",
]
`;
    const result = parseCargoLock(content);

    expect(result.packages).toHaveLength(1);
    expect(result.packages[0].name).toBe("real-app");
  });

  it("excludes [metadata] table from packages", () => {
    const content = loadFixture("v1.Cargo.lock");
    const result = parseCargoLock(content);

    expect(result.packages.every((p) => p.name !== "metadata")).toBe(true);
  });

  it("parses multi-line dependencies arrays", () => {
    const content = `
version = 3

[[package]]
name = "multi-line-app"
version = "0.1.0"
dependencies = [
 "serde",
 "tokio 1.0.0",
 # inline comment inside array
 "libc 0.2.147 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.130"
`;
    const result = parseCargoLock(content);
    const app = result.packages.find((p) => p.name === "multi-line-app");
    expect(app!.dependencies).toHaveLength(3);
  });

  it("parses quoted and escaped string values", () => {
    const content = `
version = 3

[[package]]
name = "escape-test"
version = "0.1.0"
dependencies = [
 "serde\\"special\\" 1.0.0",
]
`;
    const result = parseCargoLock(content);
    expect(result.packages[0].dependencies[0]).toBe('serde"special" 1.0.0');
  });
});

describe("parseDependencyRef", () => {
  it("parses 1-component dependency strings", () => {
    expect(parseDependencyRef("serde")).toEqual({ name: "serde" });
  });

  it("parses 2-component dependency strings", () => {
    expect(parseDependencyRef("serde 1.0.130")).toEqual({
      name: "serde",
      version: "1.0.130",
    });
  });

  it("parses 3-component dependency strings", () => {
    expect(
      parseDependencyRef(
        "serde 1.0.130 (registry+https://github.com/rust-lang/crates.io-index)",
      ),
    ).toEqual({
      name: "serde",
      version: "1.0.130",
      source: "registry+https://github.com/rust-lang/crates.io-index",
    });
  });
});

describe("resolveDependencyPackage", () => {
  const packages = [
    {
      name: "serde",
      version: "1.0.130",
      source: "registry+https://github.com/rust-lang/crates.io-index",
      dependencies: [],
    },
    {
      name: "serde",
      version: "1.0.140",
      source: "registry+https://github.com/rust-lang/crates.io-index",
      dependencies: [],
    },
  ];

  it("resolves bare name when unambiguous", () => {
    const single = [
      {
        name: "libc",
        version: "0.2.147",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        dependencies: [],
      },
    ];
    expect(resolveDependencyPackage({ name: "libc" }, single)).toEqual(
      single[0],
    );
  });

  it("skips ambiguous bare-name resolution", () => {
    expect(
      resolveDependencyPackage({ name: "serde" }, packages),
    ).toBeUndefined();
  });

  it("resolves name+version when unambiguous", () => {
    expect(
      resolveDependencyPackage({ name: "serde", version: "1.0.130" }, packages),
    ).toEqual(packages[0]);
  });
});
