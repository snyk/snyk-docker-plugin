import * as fs from "fs";
import * as path from "path";
import {
  parseCargoLock,
  CargoLock,
} from "../../../../lib/analyzer/applications/rust/cargo-lock-parser";

const fixturesPath = path.join(__dirname, "../../../fixtures/rust");

function loadFixture(subdir: string): string {
  return fs.readFileSync(
    path.join(fixturesPath, subdir, "Cargo.lock"),
    "utf-8",
  );
}

function sourceLessPackages(lock: CargoLock) {
  return lock.packages.filter((pkg) => pkg.source === undefined);
}

describe("parseCargoLock", () => {
  describe("v1 fixture", () => {
    let result: CargoLock;

    beforeAll(() => {
      result = parseCargoLock(loadFixture("v1"));
    });

    it("defaults lockfileVersion to 1", () => {
      expect(result.lockfileVersion).toBe(1);
    });

    it("parses parenthesised dependency refs with version and discards source", () => {
      const libc = result.packages.find((p) => p.name === "libc");
      expect(libc).toBeDefined();
      expect(libc!.dependencies).toContainEqual({
        name: "memchr",
        version: "2.6.4",
      });
    });

    it("ignores [metadata] table and does not emit it as a package", () => {
      expect(result.packages.some((p) => p.name === "metadata")).toBe(false);
      expect(result.packages).toHaveLength(2);
    });
  });

  describe("v2 fixture", () => {
    let result: CargoLock;

    beforeAll(() => {
      result = parseCargoLock(loadFixture("v2"));
    });

    it("defaults lockfileVersion to 1", () => {
      expect(result.lockfileVersion).toBe(1);
    });

    it("parses bare dependency refs without version", () => {
      const regex = result.packages.find((p) => p.name === "regex");
      expect(regex).toBeDefined();
      expect(regex!.dependencies).toContainEqual({ name: "memchr" });
      expect(
        regex!.dependencies.find((d) => d.name === "memchr")!.version,
      ).toBeUndefined();
    });

    it("parses multi-line dependencies arrays", () => {
      const regex = result.packages.find((p) => p.name === "regex");
      expect(regex!.dependencies).toContainEqual({ name: "regex-syntax" });
    });

    it("parses inline dependencies arrays", () => {
      const serde = result.packages.find((p) => p.name === "serde");
      expect(serde).toBeDefined();
      expect(serde!.dependencies).toContainEqual({ name: "serde_derive" });
    });

    it("ignores [[patch.unused]] blocks", () => {
      expect(result.packages.some((p) => p.name === "ignored-crate")).toBe(
        false,
      );
    });
  });

  describe("v3 fixture", () => {
    let result: CargoLock;

    beforeAll(() => {
      result = parseCargoLock(loadFixture("v3"));
    });

    it("records lockfileVersion 3 from top-level version key", () => {
      expect(result.lockfileVersion).toBe(3);
    });

    it("does not treat lockfile version as a package version", () => {
      expect(result.packages.every((p) => p.version !== "3")).toBe(true);
    });

    it("ignores per-package checksum keys", () => {
      const serde = result.packages.find((p) => p.name === "serde");
      expect(serde).toBeDefined();
      expect(serde).not.toHaveProperty("checksum");
    });
  });

  describe("v4 fixture", () => {
    let result: CargoLock;

    beforeAll(() => {
      result = parseCargoLock(loadFixture("v4"));
    });

    it("records lockfileVersion 4 from top-level version key", () => {
      expect(result.lockfileVersion).toBe(4);
    });

    it("does not treat lockfile version as a package version", () => {
      expect(result.packages.every((p) => p.version !== "4")).toBe(true);
    });

    it("parses name-version dependency refs from inline arrays", () => {
      const tokio = result.packages.find((p) => p.name === "tokio");
      expect(tokio).toBeDefined();
      expect(tokio!.dependencies).toContainEqual({
        name: "bytes",
        version: "1.5",
      });
      expect(tokio!.dependencies).toContainEqual({
        name: "pin-project-lite",
      });
    });
  });

  describe("duplicate-versions fixture", () => {
    it("yields two rand packages at different versions", () => {
      const result = parseCargoLock(loadFixture("duplicate-versions"));
      const randPackages = result.packages.filter((p) => p.name === "rand");
      expect(randPackages).toHaveLength(2);
      expect(randPackages.map((p) => p.version).sort()).toEqual([
        "0.7.3",
        "0.8.5",
      ]);
    });
  });

  describe("workspace fixture", () => {
    it("yields more than one source-less package", () => {
      const result = parseCargoLock(loadFixture("workspace"));
      const local = sourceLessPackages(result);
      expect(local.length).toBeGreaterThan(1);
      expect(local.map((p) => p.name).sort()).toEqual(["common", "my-app"]);
    });
  });

  describe("no-local-package fixture", () => {
    it("yields zero source-less packages", () => {
      const result = parseCargoLock(loadFixture("no-local-package"));
      expect(sourceLessPackages(result)).toHaveLength(0);
    });
  });

  describe("malformed fixture", () => {
    it("returns empty packages without throwing", () => {
      expect(() => parseCargoLock(loadFixture("malformed"))).not.toThrow();
      expect(parseCargoLock(loadFixture("malformed"))).toEqual({
        lockfileVersion: 1,
        packages: [],
      });
    });
  });
});
