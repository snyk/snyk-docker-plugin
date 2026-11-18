import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("ruby application scans", () => {
  it("should correctly return a rubygems application result", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult.scanResults.length).toBeGreaterThan(0);

    const rubyResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "rubygems",
    );
    expect(rubyResults).toHaveLength(1);

    const depGraphFact = rubyResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    );
    expect(depGraphFact).toBeDefined();
    expect(depGraphFact!.data.pkgManager.name).toBe("rubygems");
  });

  it("should not return Ruby manifest files when Gemfile globs are passed", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
      globsToFind: {
        include: ["**/Gemfile", "**/Gemfile.lock", "**/requirements.txt"],
        exclude: [],
      },
    });

    const rubyResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "rubygems",
    );
    expect(rubyResults).toHaveLength(1);

    const factTypes = pluginResult.scanResults[0].facts.map(
      (fact) => fact.type,
    );
    // Gemfile globs are stripped (same temporary filter as composer) so the
    // registry integration does not get a raw manifest alongside the dep graph.
    // requirements.txt remains and would produce imageManifestFiles only if
    // present in the image; this fixture has none.
    expect(factTypes).not.toContain("imageManifestFiles");
  });
});
