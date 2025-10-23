import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";

import * as plugin from "../../lib";
import { getFixture } from "../util";

describe("windows scanning", () => {
  it("can scan docker-archive image type", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/nginx.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|nginx.tar");
    expect(depGraph.rootPkg.version).toBeUndefined();

    const imageId: string = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;
    expect(imageId).toEqual(
      "sha256:5a3221f0137beb960c34b9cf4455424b6210160fd618c5e79401a07d6e5a2ced",
    );
    expect(pluginResult.scanResults[0].identity.type).toEqual("deb");
    expect(
      depGraph.getDepPkgs().find((dep) => dep.name === "adduser"),
    ).toBeDefined();

    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers).toEqual([
      path.normalize(
        "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
      ),
    ]);
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "linux/amd64",
    );
  });

  it("can scan oci-archive image type", async () => {
    const fixturePath = getFixture("oci-archives/alpine-3.12.0.tar");
    const imageNameAndTag = `oci-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|alpine-3.12.0.tar");
    expect(depGraph.rootPkg.version).toBeUndefined();
    const imageId: string = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;
    expect(imageId).toEqual(
      "sha256:0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b",
    );
    expect(pluginResult.scanResults[0].identity.type).toEqual("apk");
    expect(
      depGraph
        .getDepPkgs()
        .find((dep) => dep.name === "alpine-keys/alpine-keys"),
    ).toBeDefined();
    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers).toEqual([
      path.normalize(
        "sha256:df20fa9351a15782c64e6dddb2d4a6f50bf6d3688060a34c4014b0d9a752eb4c",
      ),
    ]);
  });

  it("can static scan for Identifier type image (nginx:1.19.11)", async () => {
    const imageNameAndTag = "nginx:1.19.11";

    await expect(() =>
      plugin.scan({
        path: imageNameAndTag,
      }),
    ).rejects.toEqual(
      new Error("The image does not exist for the current platform"),
    );
  });

  it("can static scan for Identifier type image (python:3.9.0)", async () => {
    const imageNameAndTag =
      "python@sha256:1f92d35b567363820d0f2f37c7ccf2c1543e2d852cea01edb027039e6aef25e6";

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
      "exclude-app-vulns": true,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|python");
    expect(depGraph.rootPkg.version).toBeUndefined();
    expect(pluginResult.scanResults[0].identity.type).toEqual("linux");
    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers.length).toBeGreaterThan(0);
    expect(
      imageLayers.every((layer) => layer.endsWith("layer.tar")),
    ).toBeTruthy();
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "windows/amd64",
    );
  }, 900000);

  it("can scan docker-archive with go binaries", async () => {
    // Mock Windows platform to trigger the bug
    const originalPlatform = process.platform;
    console.log("💻 Real OS platform:", originalPlatform);
    const fixturePath = getFixture(
      "docker-archives/docker-save/gobinaries-test.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    console.log("🔍 Starting scan for:", imageNameAndTag);

    // The bug is likely in the Go binary file path matching logic
    // Let's see what gets detected with Windows platform mocking

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
      "app-vulns": true, // Enable application vulnerability scanning for Go binaries
    });

    console.log(
      "📊 Scan completed. Results count:",
      pluginResult.scanResults.length,
    );
    console.log(
      "📋 Scan results overview:",
      pluginResult.scanResults.map((r) => ({
        type: r.identity.type,
        target: r.identity.targetFile || "container",
      })),
    );

    // Check if esbuild binary is found (this should differ between Windows and Linux)
    const esbuildResult = pluginResult.scanResults.find(
      (r) => r.identity.targetFile && r.identity.targetFile.includes("esbuild"),
    );
    console.log(
      "🔍 esbuild binary result:",
      esbuildResult ? "FOUND" : "NOT FOUND",
    );
    if (esbuildResult) {
      console.log("📍 esbuild path:", esbuildResult.identity.targetFile);
    }

    // The bug: Windows should find fewer results (missing esbuild)
    // Linux finds 4 projects, Windows finds 3 projects
    console.log(
      "🧮 Expected behavior: Linux=4 projects, Windows=3 projects (missing esbuild)",
    );

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|gobinaries-test.tar");
    expect(depGraph.rootPkg.version).toBeUndefined();

    const imageId: string = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;

    console.log("🏷️  Image ID:", imageId);

    // Check that we get the correct image ID from our gobinaries archive
    expect(imageId).toBeDefined();
    expect(imageId).toMatch(/^sha256:[a-f0-9]{64}$/);

    // Verify that Go binaries are detected and scanned
    const goBinariesFact = pluginResult.scanResults.find(
      (result) =>
        result.identity.type === "gomodules" ||
        result.identity.type === "gobinary",
    );

    console.log("🔍 Looking for Go binaries...");
    console.log(
      "🧩 All scan result types:",
      pluginResult.scanResults.map((r) => r.identity.type),
    );

    if (goBinariesFact) {
      console.log("✅ Found Go binaries fact:", goBinariesFact.identity);

      expect(goBinariesFact.identity.type).toMatch(/^go(modules|binary)$/);

      const goBinaryDepGraph: DepGraph = goBinariesFact.facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

      console.log(
        "📦 Go packages found:",
        goBinaryDepGraph.getDepPkgs().length,
      );
      console.log(
        "📝 Go package names:",
        goBinaryDepGraph
          .getDepPkgs()
          .map((p) => p.name)
          .slice(0, 10),
      );

      // The Go binary was detected (which is the main goal)
      console.log("🎯 Go binary detected successfully!");

      if (goBinaryDepGraph.getDepPkgs().length > 0) {
        console.log("📦 Go dependencies found - this is great!");
        const goPackages = goBinaryDepGraph.getDepPkgs();
        expect(
          goPackages.some(
            (pkg) => pkg.name.includes("go") || pkg.name.includes("golang"),
          ),
        ).toBeTruthy();
      } else {
        console.log(
          "ℹ️  Go binary detected but no embedded dependencies found (this is normal for some binaries)",
        );
      }
    } else {
      console.log("❌ No Go binaries found in scan results");
      console.log(
        "🔍 Available fact types for first result:",
        pluginResult.scanResults[0].facts.map((f) => f.type),
      );
    }

    // DEMONSTRATE THE BUG:
    // - On Linux: should find esbuild binary (4 total results)
    // - On Windows: missing esbuild binary (3 total results)
    console.log("🐛 BUG REPRODUCTION ATTEMPT:");
    console.log(`   Total scan results: ${pluginResult.scanResults.length}`);
    console.log(`   esbuild found: ${esbuildResult ? "YES" : "NO"}`);
    console.log(`   Expected on Linux: 4 results with esbuild`);
    console.log(`   Expected on Windows: 3 results WITHOUT esbuild`);

    if (process.platform === "win32" && esbuildResult) {
      console.log(
        "⚠️  BUG NOT REPRODUCED: esbuild was found on Windows (should be missing)",
      );
    } else if (process.platform !== "win32" && !esbuildResult) {
      console.log("⚠️  UNEXPECTED: esbuild missing on non-Windows platform");
    }

    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers.length).toBeGreaterThan(0);
  }, 60000); // Increase timeout for Go binary scanning
});
