import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("suse linux enterprise server tests", () => {
  afterAll(async () => {
    const slesTestImages = [
      "registry.suse.com/suse/sle15:15.2.8.2.751",
      "registry.suse.com/suse/sle15:15.3",
    ];
    for (const imageName of slesTestImages) {
      await execute("docker", ["image", "rm", imageName]).catch(() => {
        console.error(
          `tests teardown failed to remove docker image: ${imageName}`,
        );
      });
    }
  });

  it("should correctly analyze an sles image by tag", async () => {
    const image = "registry.suse.com/suse/sle15:15.2.8.2.751";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze an sle15:15.3 image", async () => {
    const image = "registry.suse.com/suse/sle15:15.3";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });

    expect(pluginResult).toMatchSnapshot();

    const scanResult = pluginResult.scanResults[0];
    expect(scanResult.identity.type).toBe("rpm");

    const osReleaseFact = scanResult.facts.find(
      (fact) => fact.type === "imageOsReleasePrettyName",
    );
    expect(osReleaseFact).toBeDefined();
    expect(osReleaseFact?.data).toContain(
      "SUSE Linux Enterprise Server 15 SP3",
    );

    const depGraphFact = scanResult.facts.find(
      (fact) => fact.type === "depGraph",
    );
    expect(depGraphFact).toBeDefined();
    expect(depGraphFact?.data?.pkgManager.name).toBe("rpm");
  });
});
