import { DepGraph } from "@snyk/dep-graph";

import * as plugin from "../../lib";

describe("windows scanning", () => {
  it("can scan a registry image (alpine:3.12.0)", async () => {
    const pluginResult = await plugin.scan({
      path: "alpine@sha256:185518070891758909c9f839cf4ca393ee977ac378609f700f60a771a2dfe321",
      platform: "linux/amd64",
      "exclude-app-vulns": true,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|alpine");
    expect(depGraph.rootPkg.version).toBeUndefined();
    expect(pluginResult.scanResults[0].identity.type).toEqual("apk");
    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers.length).toBeGreaterThan(0);
    expect(
      imageLayers.every((layer) => layer.endsWith("layer.tar")),
    ).toBeTruthy();
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "linux/amd64",
    );
  }, 900000);
});
