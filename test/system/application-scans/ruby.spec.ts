import { scan } from "../../../lib";
import { ImageManifestFilesFact } from "../../../lib/facts";
import { getFixture } from "../../util";

describe("ruby application scans", () => {
  it("should correctly return applications", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
      globsToFind: {
        include: ["**/Gemfile", "**/Gemfile.lock"],
        exclude: [],
      },
    });

    expect(pluginResult.scanResults.length).toBeGreaterThan(0);

    const rubyScanResult = pluginResult.scanResults.find(
      (scanResult) => scanResult.identity.type === "rubygems",
    );
    expect(rubyScanResult).toBeDefined();
    expect(rubyScanResult!.identity.targetFile).toMatch(/Gemfile\.lock$/);

    const depGraph = rubyScanResult!.facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.pkgManager.name).toBe("rubygems");
    expect(depGraph.getDepPkgs().length).toBeGreaterThan(0);
    expect(depGraph.getPkgs()).toEqual(
      expect.arrayContaining([
        { name: "logstash-core", version: "7.17.5-java" },
        { name: "elasticsearch", version: "7.17.1" },
        { name: "elasticsearch-api", version: "7.17.1" },
      ]),
    );
    const elasticsearchNode = depGraph
      .toJSON()
      .graph.nodes.find((node) => node.nodeId === "elasticsearch@7.17.1");
    expect(elasticsearchNode?.deps).toEqual(
      expect.arrayContaining([{ nodeId: "elasticsearch-api@7.17.1" }]),
    );

    const testedFiles = rubyScanResult!.facts.find(
      (fact) => fact.type === "testedFiles",
    );
    expect(testedFiles).toEqual({
      type: "testedFiles",
      data: ["Gemfile", "Gemfile.lock"],
    });

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
});
