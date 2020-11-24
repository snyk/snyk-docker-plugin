import { DepGraph } from "@snyk/dep-graph";
import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("imageNameAndTag tests", () => {
  it("it overrides name and version when reading a docker archive", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/nginx.tar");
    const path = `docker-archive:${fixturePath}`;
    const imageNameAndTag = "nginx:1.23.4";

    const pluginResult = await scan({
      path,
      imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|nginx");
    expect(depGraph.rootPkg.version).toEqual("1.23.4");
  });

  it("it overrides name and version when reading an oci archive", async () => {
    const fixturePath = getFixture("oci-archives/alpine-3.12.0.tar");
    const path = `oci-archive:${fixturePath}`;
    const imageNameAndTag = "nginx:1.23.4";

    const pluginResult = await scan({
      path,
      imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|nginx");
    expect(depGraph.rootPkg.version).toEqual("1.23.4");
  });

  it("it ignores imageNameAndTag when passed an image identifier", async () => {
    const path =
      "hello-world@sha256:90659bf80b44ce6be8234e6ff90a1ac34acbeb826903b02cfa0da11c82cbc042";
    // Attempting to override the "path" above
    const imageNameAndTag = "nginx:1.23.4";
    const pluginResult = await scan({
      path,
      imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|hello-world");
    expect(depGraph.rootPkg.version).toBeUndefined();
  });
});
