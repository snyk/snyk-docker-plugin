import * as path from "path";
import { scan } from "../../../../lib/index";

describe("SPDX deduplication with apt conflicts", () => {
  const imagePath = path.join(
    __dirname,
    "../../../fixtures/sbom/deduplication/spdx-conflict-test.tar.gz",
  );

  it("should prioritize apt packages over SPDX when names conflict", async () => {
    const pluginResult = await scan({
      path: `oci-archive:${imagePath}`,
    });

    expect(pluginResult).toBeDefined();
    expect(pluginResult.scanResults).toBeDefined();
    expect(pluginResult.scanResults.length).toBeGreaterThan(0);

    // Find the depGraph result
    const depGraphResult = pluginResult.scanResults.find((result) => {
      return result.facts.some((fact) => {
        if (fact.type === "depGraph") {
          return true;
        }
        return false;
      });
    });

    expect(depGraphResult).toBeDefined();

    // Get the depGraph fact
    const depGraphFact = depGraphResult?.facts.find(
      (fact) => fact.type === "depGraph",
    );
    expect(depGraphFact).toBeDefined();

    if (depGraphFact && depGraphFact.type === "depGraph") {
      const pkgs = depGraphFact.data.getPkgs();

      // Should have curl from apt
      const curlPkgs = pkgs.filter((pkg) =>
        pkg.name.toLowerCase().includes("curl"),
      );
      expect(curlPkgs.length).toBeGreaterThan(0);

      // Verify NO duplicate curl entries
      const curlNames = curlPkgs.map((pkg) => pkg.name);
      const uniqueCurlNames = new Set(curlNames);
      expect(curlNames.length).toBe(uniqueCurlNames.size);

      // The curl package should be from apt (debian), not from SPDX (dhi)
      const curlPkg = curlPkgs.find((pkg) => pkg.name === "curl");
      expect(curlPkg).toBeDefined();
      expect(curlPkg?.version).toBeDefined();
      // Apt version should have debian package format (e.g., "7.88.1-10+deb12u8")
      expect(curlPkg?.version).not.toBe("7.88.0"); // Not the exact SPDX version

      // Should have wget from apt
      const wgetPkg = pkgs.find((pkg) =>
        pkg.name.toLowerCase().includes("wget"),
      );
      expect(wgetPkg).toBeDefined();
      expect(wgetPkg?.version).toBeDefined();

      // Should have redis-server from SPDX (no conflict with apt)
      const redisPkg = pkgs.find(
        (pkg) =>
          pkg.name.toLowerCase().includes("redis-server") ||
          pkg.name.toLowerCase() === "redis-server",
      );
      expect(redisPkg).toBeDefined();
      expect(redisPkg?.version).toBe("7.0.15"); // SPDX version should be included

      // Verify total package count is reasonable
      // Should have: apt packages (curl, wget, base-files, etc.) + redis-server from SPDX
      expect(pkgs.length).toBeGreaterThan(3);
    }
  }, 120000); // 2 minute timeout for image scanning

  it("should not have duplicate packages when SPDX and apt both define the same package", async () => {
    const pluginResult = await scan({
      path: `oci-archive:${imagePath}`,
    });

    const depGraphFact = pluginResult.scanResults[0]?.facts.find(
      (fact) => fact.type === "depGraph",
    );

    if (depGraphFact && depGraphFact.type === "depGraph") {
      const pkgs = depGraphFact.data.getPkgs();
      const packageNames = pkgs.map((pkg) => pkg.name);

      // Check for duplicates by comparing array length to Set size
      const uniqueNames = new Set(packageNames);
      expect(packageNames.length).toBe(uniqueNames.size);

      // Specifically check curl is not duplicated
      const curlCount = packageNames.filter((name) =>
        name.toLowerCase().includes("curl"),
      ).length;
      expect(curlCount).toBeGreaterThan(0); // Should exist

      // No package should appear more than once
      packageNames.forEach((name) => {
        const count = packageNames.filter((n) => n === name).length;
        expect(count).toBe(1);
      });
    }
  }, 120000);
});
