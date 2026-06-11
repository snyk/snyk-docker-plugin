import { DepGraph } from "@snyk/dep-graph";

import * as plugin from "../../lib";

describe("windows scanning", () => {
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
});
