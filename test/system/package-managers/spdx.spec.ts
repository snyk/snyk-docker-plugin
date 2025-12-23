import * as path from "path";
import { AnalysisType } from "../../../lib/analyzer/types";
import { scan } from "../../../lib/index";

describe("SPDX (Docker Hardened Images) package manager tests", () => {
  const imagePath = path.join(
    __dirname,
    "../../fixtures/sbom/simple/dhi-test.tar",
  );

  it("should correctly analyze SPDX files from a Docker Hardened Image", async () => {
    const pluginResult = await scan({
      path: `oci-archive:${imagePath}`,
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

      // Should have detected redis-tools package from SPDX
      const redisToolsPkg = pkgs.find((pkg) =>
        pkg.name.toLowerCase().includes("redis-tools"),
      );
      expect(redisToolsPkg).toBeDefined();

      // Should have detected redis-server package from SPDX
      const redisServerPkg = pkgs.find((pkg) =>
        pkg.name.toLowerCase().includes("redis-server"),
      );
      expect(redisServerPkg).toBeDefined();
    }
  }, 120000); // 2 minute timeout for pulling and scanning image
});
