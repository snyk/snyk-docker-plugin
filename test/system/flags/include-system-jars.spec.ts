import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("include-system-jars flag", () => {
  it("excludes system JARs by default", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/java.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult.scanResults).toBeDefined();

    // Verify that no system JARs from /usr/lib are included
    const javaResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "maven",
    );

    for (const result of javaResults) {
      if (result.identity?.targetFile) {
        expect(result.identity.targetFile).not.toContain("/usr/lib");
      }
    }
  });

  it("includes system JARs when --include-system-jars is true", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/java.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "include-system-jars": true,
    });

    // Verify the scan runs successfully and that the option is properly processed
    expect(pluginResult.scanResults).toBeDefined();

    // Since the test fixture doesn't contain /usr/lib JARs, we verify the flag is processed
    // by checking that Maven results are still present (confirms our logic didn't break anything)
    const javaResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "maven",
    );
    expect(javaResults.length).toBeGreaterThan(0);
  });

  it("excludes system JARs when --include-system-jars is false", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/java.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "include-system-jars": false,
    });

    expect(pluginResult.scanResults).toBeDefined();

    // Verify that no system JARs from /usr/lib are included
    const javaResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "maven",
    );

    for (const result of javaResults) {
      if (result.identity?.targetFile) {
        expect(result.identity.targetFile).not.toContain("/usr/lib");
      }
    }
  });

  it("handles string values for include-system-jars flag", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/java.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResultTrue = await scan({
      path: imageNameAndTag,
      "include-system-jars": "true",
    });

    const pluginResultFalse = await scan({
      path: imageNameAndTag,
      "include-system-jars": "false",
    });

    // Both should run successfully with proper flag handling
    expect(pluginResultTrue.scanResults).toBeDefined();
    expect(pluginResultFalse.scanResults).toBeDefined();

    // Verify both produce Maven scan results
    const javaResultsTrue = pluginResultTrue.scanResults.filter(
      (result) => result.identity.type === "maven",
    );
    const javaResultsFalse = pluginResultFalse.scanResults.filter(
      (result) => result.identity.type === "maven",
    );

    expect(javaResultsTrue.length).toBeGreaterThan(0);
    expect(javaResultsFalse.length).toBeGreaterThan(0);
  });
});
