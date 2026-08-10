import { readFileSync } from "fs";
import { join } from "path";

import { cargoFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { DepGraphFact, TestedFilesFact } from "../../../lib/facts";

const fixturesRoot = join(__dirname, "../../fixtures/cargo");

function getDepGraphFact(
  facts: Array<{ type: string; data: unknown }>,
): DepGraphFact {
  return facts.find((fact) => fact.type === "depGraph") as DepGraphFact;
}

function getTestedFilesFact(
  facts: Array<{ type: string; data: unknown }>,
): TestedFilesFact {
  return facts.find((fact) => fact.type === "testedFiles") as TestedFilesFact;
}

describe("cargoFilesToScannedProjects", () => {
  it("builds a depGraph from a valid Cargo.lock", async () => {
    const lockContent = readFileSync(
      join(fixturesRoot, "standard/Cargo.lock"),
      "utf8",
    );

    const scanResults = await cargoFilesToScannedProjects({
      "/app/Cargo.lock": lockContent,
    });

    expect(scanResults).toHaveLength(1);
    const [result] = scanResults;
    expect(result.identity).toEqual({
      type: "cargo",
      targetFile: "/app/Cargo.lock",
    });

    const pkgs = getDepGraphFact(result.facts).data.getDepPkgs();
    expect(pkgs).toEqual(
      expect.arrayContaining([
        { name: "log", version: "0.4.17" },
        { name: "serde", version: "1.0.150" },
      ]),
    );
    expect(getTestedFilesFact(result.facts).data).toEqual(["Cargo.lock"]);
  });

  it("returns no results when only Cargo.toml is present", async () => {
    const scanResults = await cargoFilesToScannedProjects({
      "/app/Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"',
    });

    expect(scanResults).toEqual([]);
  });

  it("returns no results for an empty Cargo.lock", async () => {
    const lockContent = readFileSync(
      join(fixturesRoot, "empty/Cargo.lock"),
      "utf8",
    );

    const scanResults = await cargoFilesToScannedProjects({
      "/app/Cargo.lock": lockContent,
    });

    expect(scanResults).toEqual([]);
  });

  it("returns no results for a malformed Cargo.lock", async () => {
    const lockContent = readFileSync(
      join(fixturesRoot, "malformed/Cargo.lock"),
      "utf8",
    );

    const scanResults = await cargoFilesToScannedProjects({
      "/app/Cargo.lock": lockContent,
    });

    expect(scanResults).toEqual([]);
  });

  it("deduplicates packages with identical name and version", async () => {
    const lockContent = readFileSync(
      join(fixturesRoot, "duplicate-packages/Cargo.lock"),
      "utf8",
    );

    const scanResults = await cargoFilesToScannedProjects({
      "/app/Cargo.lock": lockContent,
    });

    expect(scanResults).toHaveLength(1);
    const pkgs = getDepGraphFact(scanResults[0].facts).data.getDepPkgs();

    const logEntries = pkgs.filter(
      (pkg) => pkg.name === "log" && pkg.version === "0.4.17",
    );
    expect(logEntries).toHaveLength(1);

    const emptyKeyEntries = pkgs.filter(
      (pkg) => pkg.name === "" && pkg.version === "",
    );
    expect(emptyKeyEntries.length).toBeLessThanOrEqual(1);
  });
});
