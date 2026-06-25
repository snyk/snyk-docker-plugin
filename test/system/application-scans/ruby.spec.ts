import { scan } from "../../../lib";
import { DepGraphFact, ImageManifestFilesFact } from "../../../lib/facts";
import { getFixture } from "../../util";

describe("ruby application scans", () => {
  const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
  const imageNameAndTag = `docker-archive:${fixturePath}`;

  it("returns a rubygems dependency graph from the Gemfile.lock", async () => {
    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    const rubyScanResult = pluginResult.scanResults.find(
      (scanResult) => scanResult.identity.type === "rubygems",
    );
    expect(rubyScanResult).toBeDefined();
    expect(rubyScanResult!.identity.targetFile).toMatch(/Gemfile\.lock$/);

    const testedFiles = rubyScanResult!.facts.find(
      (fact) => fact.type === "testedFiles",
    );
    expect(testedFiles).toEqual({
      type: "testedFiles",
      data: ["Gemfile", "Gemfile.lock"],
    });

    const depGraph = (
      rubyScanResult!.facts.find(
        (fact) => fact.type === "depGraph",
      )! as DepGraphFact
    ).data;
    expect(depGraph.pkgManager.name).toBe("rubygems");
    expect(depGraph.getDepPkgs().length).toBeGreaterThan(0);
    expect(depGraph.getPkgs()).toEqual(
      expect.arrayContaining([
        { name: "logstash-core", version: "7.17.5-java" },
        { name: "elasticsearch", version: "7.17.1" },
        { name: "elasticsearch-api", version: "7.17.1" },
      ]),
    );

    // Spot-check a real transitive edge to prove the graph is connected, not flat.
    const elasticsearchNode = depGraph
      .toJSON()
      .graph.nodes.find((node) => node.nodeId === "elasticsearch@7.17.1");
    expect(elasticsearchNode?.deps).toEqual(
      expect.arrayContaining([{ nodeId: "elasticsearch-api@7.17.1" }]),
    );
  });

  it("still passes Gemfile manifests through when globs are requested", async () => {
    // Native Ruby scanning and the imageManifestFiles passthrough coexist; we do
    // not dedupe the Gemfile globs the way composer does.
    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
      globsToFind: {
        include: ["**/Gemfile", "**/Gemfile.lock"],
        exclude: [],
      },
    });

    const rubyScanResult = pluginResult.scanResults.find(
      (scanResult) => scanResult.identity.type === "rubygems",
    );
    expect(rubyScanResult).toBeDefined();

    const imageManifestFiles = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageManifestFiles",
    )! as ImageManifestFilesFact;
    expect(imageManifestFiles).toBeDefined();

    const manifestFile = imageManifestFiles.data.find(
      (manifest) => manifest.name === "Gemfile.lock",
    )!;
    expect(manifestFile).toBeDefined();

    const decodedContents = Buffer.from(manifestFile.contents, "base64");
    const gemfileLock = decodedContents.toString("utf8");
    // This is testing for a specific bug with our extraction logic.
    // Previously the length would be less than half of this number due to a bug in the encoding logic.
    expect(gemfileLock.length).toEqual(28180);
  });

  it("does not scan Ruby applications when app vulns are excluded", async () => {
    const pluginResult = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": true,
    });

    const rubyScanResult = pluginResult.scanResults.find(
      (scanResult) => scanResult.identity.type === "rubygems",
    );
    expect(rubyScanResult).toBeUndefined();
  });
});
