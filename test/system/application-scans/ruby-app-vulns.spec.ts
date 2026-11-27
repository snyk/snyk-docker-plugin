import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("ruby application vulnerability scans", () => {
  it("should return a rubygems dep graph from Gemfile.lock with app-vulns", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    const rubyResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "rubygems",
    );
    expect(rubyResults).toHaveLength(1);

    const depGraphFact = rubyResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    );
    expect(depGraphFact).toBeDefined();
    expect(depGraphFact!.data.pkgManager.name).toBe("rubygems");

    const pkgs = depGraphFact!.data.getPkgs();
    expect(
      pkgs.find((p) => p.name === "addressable" && p.version === "2.8.0"),
    ).toBeDefined();
    expect(
      pkgs.find((p) => p.name === "sinatra" && p.version === "2.1.0"),
    ).toBeDefined();

    const testedFilesFact = rubyResults[0].facts.find(
      (fact) => fact.type === "testedFiles",
    );
    expect(testedFilesFact).toBeDefined();
    expect(testedFilesFact!.data).toContain("Gemfile.lock");
  });

  it("should not return a Ruby result when exclude-app-vulns is true", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": true,
    });

    const rubyResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "rubygems",
    );
    expect(rubyResults).toHaveLength(0);
  });
});
