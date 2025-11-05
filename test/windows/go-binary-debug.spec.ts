import * as path from "path";

import * as plugin from "../../lib";
import { extractImageContent } from "../../lib/extractor";
import {
  getGoModulesContentAction,
  goModulesToScannedProjects,
} from "../../lib/go-parser";
import { ImageType } from "../../lib/types";
import { getFixture } from "../util";

describe("Go Binary Detection Debug (Windows)", () => {
  const fixturePath = getFixture("docker-archives/docker-save/go-binaries.tar");
  const imageNameAndTag = `docker-archive:${fixturePath}`;

  beforeAll(() => {
    console.log("🔍 === GO BINARY DEBUG TEST STARTING ===");
    console.log(`🔍 Test running on platform: ${process.platform}`);
    console.log(`🔍 Node.js path.sep: "${path.sep}"`);
    console.log(`🔍 POSIX path.sep: "${path.posix.sep}"`);
    console.log(`🔍 Test fixture path: ${fixturePath}`);
  });

  afterAll(() => {
    console.log("🔍 === GO BINARY DEBUG TEST COMPLETED ===");
  });

  it("should debug full scan process and output goModulesToScannedProjects results", async () => {
    console.log("\n🔍 === Starting full plugin scan ===");

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    console.log("\n🔍 === Plugin scan completed ===");
    console.log("🔍 Plugin result structure:");
    console.log(
      `🔍   scanResults.length: ${pluginResult.scanResults?.length || 0}`,
    );

    if (pluginResult.scanResults) {
      pluginResult.scanResults.forEach((result, index) => {
        console.log(`🔍   scanResult[${index}]:`);
        console.log(`🔍     identity.type: ${result.identity.type}`);
        console.log(
          `🔍     identity.targetFile: ${result.identity.targetFile || "N/A"}`,
        );
        console.log(`🔍     facts.length: ${result.facts?.length || 0}`);

        const depGraphFact = result.facts?.find((f) => f.type === "depGraph");
        if (depGraphFact) {
          console.log(
            `🔍     depGraph.rootPkg.name: ${depGraphFact.data?.rootPkg?.name}`,
          );
          console.log(
            `🔍     depGraph.deps.length: ${
              depGraphFact.data?.getDepPkgs?.()?.length || 0
            }`,
          );
        }
      });
    }

    // Output the result for inspection
    console.log("\n🔍 === Full Plugin Result JSON ===");
    console.log(JSON.stringify(pluginResult, null, 2));

    expect(pluginResult).toBeDefined();
  }, 300000); // 5 minute timeout

  it("should debug direct Go binary extraction and processing", async () => {
    console.log("\n🔍 === Starting direct Go binary extraction ===");

    try {
      // Extract content directly using the Go modules action
      const extractionResult = await extractImageContent(
        ImageType.DockerArchive,
        fixturePath,
        [getGoModulesContentAction],
        { "app-vulns": true },
      );

      console.log("\n🔍 === Extraction completed ===");
      console.log("🔍 extractionResult.extractedLayers keys:");
      console.log(Object.keys(extractionResult.extractedLayers));

      // Look for gomodules content specifically
      const goModulesContent = {};
      Object.entries(extractionResult.extractedLayers).forEach(
        ([filePath, layerContent]) => {
          if (layerContent && layerContent.gomodules) {
            console.log(`🔍 Found gomodules content at: ${filePath}`);
            goModulesContent[filePath] = layerContent.gomodules;
          }
        },
      );

      console.log("\n🔍 === Go Modules Content Found ===");
      console.log("🔍 goModulesContent keys:", Object.keys(goModulesContent));

      if (Object.keys(goModulesContent).length > 0) {
        console.log("\n🔍 === Processing with goModulesToScannedProjects ===");
        const scannedProjects = await goModulesToScannedProjects(
          goModulesContent,
        );

        console.log("\n🔍 === goModulesToScannedProjects Results ===");
        console.log("🔍 scannedProjects.length:", scannedProjects.length);

        scannedProjects.forEach((project, index) => {
          console.log(`🔍 Project[${index}]:`);
          console.log(`🔍   identity.type: ${project.identity.type}`);
          console.log(
            `🔍   identity.targetFile: ${project.identity.targetFile}`,
          );
          console.log(`🔍   facts.length: ${project.facts?.length || 0}`);

          const depGraphFact = project.facts?.find(
            (f) => f.type === "depGraph",
          );
          if (depGraphFact) {
            console.log(
              `🔍   depGraph.rootPkg.name: ${depGraphFact.data?.rootPkg?.name}`,
            );
            console.log(
              `🔍   depGraph.deps.length: ${
                depGraphFact.data?.getDepPkgs?.()?.length || 0
              }`,
            );
          }
        });

        console.log("\n🔍 === Full scannedProjects JSON ===");
        console.log(JSON.stringify(scannedProjects, null, 2));

        // Test expectations
        expect(scannedProjects).toBeDefined();
        expect(Array.isArray(scannedProjects)).toBe(true);

        // Log whether we found any Go projects
        if (scannedProjects.length === 0) {
          console.log(
            "🔍 ❌ WARNING: No Go projects found in scannedProjects!",
          );
        } else {
          console.log(
            `🔍 ✅ SUCCESS: Found ${scannedProjects.length} Go project(s)`,
          );
        }
      } else {
        console.log(
          "🔍 ❌ WARNING: No Go modules content found in extracted layers!",
        );

        // Let's also log all the file paths that were extracted
        console.log("\n🔍 === All Extracted File Paths ===");
        Object.keys(extractionResult.extractedLayers).forEach((filePath) => {
          console.log(`🔍 Extracted file: ${filePath}`);
        });
      }
    } catch (error) {
      console.log(`🔍 ❌ ERROR during extraction: ${error.message}`);
      console.log(`🔍 Error stack: ${error.stack}`);
      throw error;
    }
  }, 300000); // 5 minute timeout

  it("should check specific esbuild path handling", async () => {
    console.log("\n🔍 === Testing esbuild path handling ===");

    const testPaths = [
      "/app/node_modules/.pnpm/@esbuild+linux-x64@0.23.1/node_modules/@esbuild/linux-x64/bin/esbuild",
      "\\app\\node_modules\\.pnpm\\@esbuild+linux-x64@0.23.1\\node_modules\\@esbuild\\linux-x64\\bin\\esbuild",
      "app/node_modules/.pnpm/@esbuild+linux-x64@0.23.1/node_modules/@esbuild/linux-x64/bin/esbuild",
    ];

    testPaths.forEach((testPath) => {
      console.log(`\n🔍 Testing path: "${testPath}"`);

      // Test path normalization
      const normalizedStandard = path.normalize(testPath);
      const normalizedPosix = path.posix.normalize(testPath);

      console.log(`🔍   path.normalize(): "${normalizedStandard}"`);
      console.log(`🔍   path.posix.normalize(): "${normalizedPosix}"`);

      // Test path joining behavior
      const joinedStandard = path.join(path.sep, testPath);
      const joinedPosix = path.posix.join("/", testPath);

      console.log(`🔍   path.join(path.sep, testPath): "${joinedStandard}"`);
      console.log(`🔍   path.posix.join("/", testPath): "${joinedPosix}"`);

      // Test file path matching
      // Note: filePathMatches is not exported, so we'll test the action instead
      const matches = getGoModulesContentAction.filePathMatches(testPath);
      console.log(`🔍   filePathMatches result: ${matches}`);
    });
  });
});
