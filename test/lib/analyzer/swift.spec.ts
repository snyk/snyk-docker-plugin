import * as fs from "fs";
import * as path from "path";
import { swiftFilesToScannedProjects } from "../../../lib/analyzer/applications/swift";

const fixturesPath = path.join(__dirname, "../../fixtures/swift");

function loadFixture(filename: string): string {
  return fs.readFileSync(path.join(fixturesPath, filename), "utf-8");
}

describe("Swift Package.resolved analyzer", () => {
  describe("v1 lockfile", () => {
    it("should produce a scan result with a swift identity", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV1.resolved"),
      });

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("swift");
      expect(results[0].identity.targetFile).toBe("/app/Package.resolved");
    });

    it("should include the testedFiles fact", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV1.resolved"),
      });

      const testedFilesFact = results[0].facts.find(
        (f) => f.type === "testedFiles",
      );
      expect(testedFilesFact!.data).toEqual(["Package.resolved"]);
    });

    it("should include the versioned pin, named from the repository URL", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV1.resolved"),
      });

      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      const pkgs = depGraph.getPkgs();
      const swiftLog = pkgs.find((p) => p.name === "swift-log");
      expect(swiftLog).toBeDefined();
      expect(swiftLog!.version).toBe("1.5.4");
    });

    it("should skip a pin with no resolved version (branch/revision pin)", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV1.resolved"),
      });

      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      const pkgs = depGraph.getPkgs();
      expect(pkgs.some((p) => p.name === "swift-nio")).toBe(false);
    });
  });

  describe("v2 lockfile", () => {
    it("should produce a scan result naming pins from identity", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV2.resolved"),
      });

      expect(results).toHaveLength(1);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      const pkgs = depGraph.getPkgs();
      const swiftLog = pkgs.find((p) => p.name === "swift-log");
      expect(swiftLog).toBeDefined();
      expect(swiftLog!.version).toBe("1.5.4");
    });

    it("should skip a pin with no resolved version", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV2.resolved"),
      });

      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      const pkgs = depGraph.getPkgs();
      expect(pkgs.some((p) => p.name === "swift-algorithms")).toBe(false);
    });

    it("should yield the same package name as an equivalent v1 pin for the same repo", async () => {
      const v1Results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV1.resolved"),
      });
      const v2Results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV2.resolved"),
      });

      const v1Pkgs = v1Results[0].facts
        .find((f) => f.type === "depGraph")!
        .data.getPkgs();
      const v2Pkgs = v2Results[0].facts
        .find((f) => f.type === "depGraph")!
        .data.getPkgs();

      expect(v1Pkgs.some((p) => p.name === "swift-log")).toBe(true);
      expect(v2Pkgs.some((p) => p.name === "swift-log")).toBe(true);
    });
  });

  describe("v3 lockfile", () => {
    it("should parse pins and ignore the top-level originHash", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": loadFixture("PackageV3.resolved"),
      });

      expect(results).toHaveLength(1);
      const depGraph = results[0].facts.find(
        (f) => f.type === "depGraph",
      )!.data;
      const pkgs = depGraph.getPkgs();
      const swiftLog = pkgs.find((p) => p.name === "swift-log");
      expect(swiftLog).toBeDefined();
      expect(swiftLog!.version).toBe("1.5.4");
    });
  });

  describe("edge cases", () => {
    it("should return empty array for empty input", async () => {
      const results = await swiftFilesToScannedProjects({});
      expect(results).toHaveLength(0);
    });

    it("should handle invalid JSON gracefully", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": "not valid json{{{",
      });
      expect(results).toHaveLength(0);
    });

    it("should skip a file with an unrecognised version", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": JSON.stringify({ version: 99, pins: [] }),
      });
      expect(results).toHaveLength(0);
    });

    it("should skip a file where every pin lacks a resolved version", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app/Package.resolved": JSON.stringify({
          version: 2,
          pins: [
            {
              identity: "swift-nio",
              location: "https://github.com/apple/swift-nio.git",
              state: { branch: "main", revision: "abc123" },
            },
          ],
        }),
      });
      expect(results).toHaveLength(0);
    });

    it("should handle multiple Package.resolved files", async () => {
      const results = await swiftFilesToScannedProjects({
        "/app1/Package.resolved": loadFixture("PackageV1.resolved"),
        "/app2/Package.resolved": loadFixture("PackageV2.resolved"),
      });
      expect(results).toHaveLength(2);
    });
  });
});
