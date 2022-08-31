import { DepGraph } from "@snyk/dep-graph";

import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("compressed archive scanning", () => {
  it("should correctly scan a compressed archive", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/nginx-compressed-layers.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should match the results of a normal archive", async () => {
    const compressedFixturePath = getFixture(
      "docker-archives/skopeo-copy/nginx-compressed-layers.tar",
    );
    const compressedImageNameAndTag = `docker-archive:${compressedFixturePath}`;
    const compressedPluginResult = await scan({
      path: compressedImageNameAndTag,
    });

    const fixturePath = getFixture("docker-archives/skopeo-copy/nginx.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;
    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(compressedPluginResult.scanResults.length).toEqual(
      pluginResult.scanResults.length,
    );

    const compressedPluginResultDepGraph: DepGraph =
      compressedPluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    const pluginResultDepGraph: DepGraph =
      pluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    expect(compressedPluginResultDepGraph.getDepPkgs().sort()).toEqual(
      pluginResultDepGraph.getDepPkgs().sort(),
    );
  });
});
