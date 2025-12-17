import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("target-reference flag", () => {
  it("applies target-reference to OS scan result", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;
    const targetReference = "my-custom-reference";

    const pluginResult = await scan({
      path: imageNameAndTag,
      "target-reference": targetReference,
      "exclude-app-vulns": true,
    });

    expect(pluginResult.scanResults).toHaveLength(1);

    // OS scan result should have targetReference
    const osScanResult = pluginResult.scanResults[0];
    expect(osScanResult.targetReference).toEqual(targetReference);
  });

  it("applies target-reference to both OS and application scan results", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;
    const targetReference = "my-custom-reference";

    const pluginResult = await scan({
      path: imageNameAndTag,
      "target-reference": targetReference,
    });

    // Should have OS scan result + application scan results
    expect(pluginResult.scanResults.length).toBeGreaterThan(1);

    // All scan results should have the targetReference
    for (const scanResult of pluginResult.scanResults) {
      expect(scanResult.targetReference).toEqual(targetReference);
    }
  });

  it("does not include targetReference when option is not provided", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    // Should have OS scan result + application scan results
    expect(pluginResult.scanResults.length).toBeGreaterThan(1);

    // No scan results should have targetReference
    for (const scanResult of pluginResult.scanResults) {
      expect(scanResult.targetReference).toBeUndefined();
    }
  });
});
