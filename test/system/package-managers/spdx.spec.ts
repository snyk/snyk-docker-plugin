import * as path from "path";
import { scan } from "../../../lib/index";
import { AnalysisType } from "../../../lib/analyzer/types";

describe("SPDX (Docker Hardened Images) package manager tests", () => {
  const imagePath = path.join(
    __dirname,
    "../../fixtures/sbom/simple/dhi-test.tar",
  );

  it("should correctly analyze SPDX files from a Docker Hardened Image", async () => {
    const pluginResult = await scan({
      path: `snyklabs/dhi-python:3.13.8-debian13-dev`,
      platform: "linux/arm64",
    });

    expect(pluginResult).toBeDefined();
    expect(pluginResult.scanResults).toBeDefined();
    expect(pluginResult.scanResults.length).toBeGreaterThan(0);

    // Find the SPDX scan result
    const depGraphResult = pluginResult.scanResults.find((result) => {
      return result.facts.some((fact) => {
        if (fact.type === "depGraph") {
          return true;
        }
        return false;
      });
    });

    // Verify depGraph result exists
    expect(depGraphResult).toBeDefined();

    // Get the depGraph fact
    const depGraphFact = depGraphResult?.facts.find(
      (fact) => fact.type === "depGraph",
    );
    expect(depGraphFact).toBeDefined();

    if (depGraphFact && depGraphFact.type === "depGraph") {
      const pkgs = depGraphFact.data.getPkgs();

      // Should have detected python package from SPDX
      const pythonPkg = pkgs.find((pkg) =>
        pkg.name.toLowerCase().includes("python"),
      );
      expect(pythonPkg).toBeDefined();

      // Should have detected pkg-binutils package from SPDX
      const pkgBinutilsPkg = pkgs.find((pkg) =>
        pkg.name.toLowerCase().includes("pkg-binutils"),
      );
      expect(pkgBinutilsPkg).toBeDefined();
    }
  }, 120000); // 2 minute timeout for pulling and scanning image
});

