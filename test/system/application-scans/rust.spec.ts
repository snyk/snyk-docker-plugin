import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("rust application scans", () => {
  it("should correctly return the Cargo.lock scan result", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/rust.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult.scanResults).toHaveLength(2);

    const cargoResult = pluginResult.scanResults.find(
      (result) => result.identity.type === "cargo",
    );
    expect(cargoResult).toBeDefined();
    expect(cargoResult!.identity.targetFile).toBe("/app/Cargo.lock");

    const depGraphFact = cargoResult!.facts.find(
      (fact) => fact.type === "depGraph",
    );
    expect(depGraphFact).toBeDefined();
    expect(depGraphFact!.data.rootPkg.name).toBe("fixture-app");
    expect(depGraphFact!.data.rootPkg.version).toBe("0.1.0");

    const pkgs = depGraphFact!.data.getPkgs();
    expect(pkgs.find((p) => p.name === "log" && p.version === "0.4.20")).toBeDefined();

    const testedFilesFact = cargoResult!.facts.find(
      (fact) => fact.type === "testedFiles",
    );
    expect(testedFilesFact!.data).toEqual(["Cargo.lock"]);
  });

  it("should handle --exclude-app-vulns", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/rust.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": true,
    });

    expect(pluginResult.scanResults).toHaveLength(1);
    expect(
      pluginResult.scanResults.find(
        (result) => result.identity.type === "cargo",
      ),
    ).toBeUndefined();
  });
});
