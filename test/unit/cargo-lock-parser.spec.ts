import { DepGraphBuilder } from "@snyk/dep-graph";
import { readFileSync } from "fs";
import { join } from "path";
import { parseCargoLock } from "../../lib/cargo-parser/cargo-lock-parser";

const fixturesRoot = join(__dirname, "../fixtures/cargo");

function readFixture(relativePath: string): string {
  return readFileSync(join(fixturesRoot, relativePath), "utf8");
}

describe("cargo lock parser", () => {
  it("parses a well-formed Cargo.lock with inline and multi-line dependency arrays", () => {
    const cargoLock = readFixture("standard/Cargo.lock");

    const result = parseCargoLock(cargoLock);

    expect(result).toEqual([
      {
        name: "app",
        version: "0.1.0",
        dependencies: [{ name: "log" }, { name: "serde", version: "1.0.150" }],
      },
      {
        name: "log",
        version: "0.4.17",
        dependencies: [],
      },
      {
        name: "serde",
        version: "1.0.150",
        dependencies: [],
      },
    ]);
  });

  it("emits workspace members with no source field the same as registry packages", () => {
    const cargoLock = readFixture("workspace/Cargo.lock");

    const result = parseCargoLock(cargoLock);

    expect(result).toEqual([
      {
        name: "workspace-member",
        version: "0.1.0",
        dependencies: [{ name: "shared-lib" }],
      },
      {
        name: "shared-lib",
        version: "0.1.0",
        dependencies: [],
      },
      {
        name: "external-dep",
        version: "2.3.4",
        dependencies: [],
      },
    ]);
  });

  it("does not treat a '#' inside a quoted git source fragment as a comment", () => {
    const cargoLock = readFixture("git-source/Cargo.lock");

    const result = parseCargoLock(cargoLock);

    expect(result).toEqual([
      {
        name: "app",
        version: "0.1.0",
        dependencies: [{ name: "rand", version: "0.8.5" }],
      },
      {
        name: "rand",
        version: "0.8.5",
        dependencies: [],
      },
    ]);
  });

  it("returns an empty array for a Cargo.lock with an unterminated string", () => {
    const cargoLock = readFixture("malformed/Cargo.lock");

    expect(() => parseCargoLock(cargoLock)).not.toThrow();
    expect(parseCargoLock(cargoLock)).toEqual([]);
  });

  it("returns an empty array for a Cargo.lock with an unclosed dependencies array", () => {
    const cargoLock = readFixture("unclosed-array/Cargo.lock");

    expect(parseCargoLock(cargoLock)).toEqual([]);
  });

  it("returns an empty array for missing or empty input", () => {
    expect(parseCargoLock(undefined)).toEqual([]);
    expect(parseCargoLock(null)).toEqual([]);
    expect(parseCargoLock("")).toEqual([]);
  });

  it("can be used to build a dep-graph from parsed packages", () => {
    const cargoLock = readFixture("standard/Cargo.lock");
    const packages = parseCargoLock(cargoLock);

    const builder = new DepGraphBuilder({ name: "cargo" }, { name: "app" });
    for (const pkg of packages) {
      builder.addPkgNode(
        { name: pkg.name, version: pkg.version },
        `${pkg.name}@${pkg.version}`,
      );
    }
    for (const pkg of packages) {
      for (const dep of pkg.dependencies) {
        const target = packages.find((candidate) => candidate.name === dep.name);
        if (!target) {
          continue;
        }
        builder.connectDep(
          `${pkg.name}@${pkg.version}`,
          `${target.name}@${target.version}`,
        );
      }
    }
    builder.connectDep(builder.rootNodeId, "app@0.1.0");

    const depGraph = builder.build();

    expect(depGraph.rootPkg.name).toBe("app");
    expect(depGraph.getDepPkgs()).toEqual(
      expect.arrayContaining([
        { name: "app", version: "0.1.0" },
        { name: "log", version: "0.4.17" },
        { name: "serde", version: "1.0.150" },
      ]),
    );
  });
});
