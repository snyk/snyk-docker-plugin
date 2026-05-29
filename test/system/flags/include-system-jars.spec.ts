import { scan } from "../../../lib";
import { ScanResult } from "../../../lib/types";
import { getFixture } from "../../util";

describe("include-system-jars flag", () => {
  // This fixture holds a normal jar (/app/activation-1.1.1.jar) and a system jar
  // (/usr/lib/aopalliance-repackaged-2.5.0.jar). The system jar is only picked up
  // when --include-system-jars is set, which the snapshots below characterize.
  const fixturePath = getFixture(
    "docker-archives/docker-save/java-system-jars.tar",
  );
  const imageNameAndTag = `docker-archive:${fixturePath}`;
  const systemJarTarget = "/usr/lib";

  const mavenTargets = (result: { scanResults: ScanResult[] }) =>
    result.scanResults
      .filter((r) => r.identity.type === "maven")
      .map((r) => r.identity.targetFile);

  it("excludes /usr/lib JARs by default", async () => {
    const pluginResult = await scan({ path: imageNameAndTag });

    expect(mavenTargets(pluginResult)).not.toContain(systemJarTarget);
    expect(pluginResult).toMatchSnapshot();
  });

  it("includes /usr/lib JARs when --include-system-jars is true", async () => {
    const pluginResult = await scan({
      path: imageNameAndTag,
      "include-system-jars": true,
    });

    expect(mavenTargets(pluginResult)).toContain(systemJarTarget);
    expect(pluginResult).toMatchSnapshot();
  });

  it("excludes /usr/lib JARs when --include-system-jars is false", async () => {
    const pluginResult = await scan({
      path: imageNameAndTag,
      "include-system-jars": false,
    });

    expect(mavenTargets(pluginResult)).not.toContain(systemJarTarget);
  });

  it("handles string values for include-system-jars flag", async () => {
    const pluginResultTrue = await scan({
      path: imageNameAndTag,
      "include-system-jars": "true",
    });
    const pluginResultFalse = await scan({
      path: imageNameAndTag,
      "include-system-jars": "false",
    });

    expect(mavenTargets(pluginResultTrue)).toContain(systemJarTarget);
    expect(mavenTargets(pluginResultFalse)).not.toContain(systemJarTarget);
  });
});
