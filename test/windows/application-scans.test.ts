import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";

function getFixture(fixturePath: string): string {
  return path.join(__dirname, "../fixtures", fixturePath);
}

test("scanning a container image with 2 applications", async (t) => {
  const fixturePath = getFixture(
    "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
  );
  const imageNameAndTag = `docker-archive:${fixturePath}`;

  const pluginResult = await plugin.scan({
    path: imageNameAndTag,
    "app-vulns": true,
  });

  t.ok(
    "scanResults" in pluginResult && Array.isArray(pluginResult.scanResults),
    "scanResults is in plugin response and has the correct type",
  );
  t.same(pluginResult.scanResults.length, 3, "contains 3 scan results");

  const npmScan = pluginResult.scanResults[1];
  await t.test("first scanned project is scanned correctly", async (subt) => {
    subt.same(
      npmScan.identity.type,
      "npm",
      "npm as package manager is scanned correctly",
    );
    subt.same(
      npmScan.identity.targetFile,
      path.normalize("/srv/npm-app/package.json"),
      "path to targetFile is correct",
    );

    const depGraphFact = npmScan.facts.find((fact) => fact.type === "depGraph");
    subt.ok(
      depGraphFact !== undefined,
      "scan result contains a dependency graph",
    );
    const depGraph: DepGraph = depGraphFact!.data;
    subt.same(
      depGraph.toJSON(),
      require(getFixture("analysis-results/npm.json")),
      "returned dependency graph is the same",
    );
  });

  const yarnScan = pluginResult.scanResults[2];
  await t.test("second scanned project is scanned correctly", async (subt) => {
    subt.same(
      yarnScan.identity.type,
      "yarn",
      "yarn as package manager is scanned correctly",
    );
    subt.same(
      yarnScan.identity.targetFile,
      path.normalize("/srv/yarn-app/package.json"),
      "path to targetFile is correct",
    );
    const depGraphFact = yarnScan.facts.find(
      (fact) => fact.type === "depGraph",
    );
    subt.ok(
      depGraphFact !== undefined,
      "scan result contains a dependency graph",
    );
    const depGraph: DepGraph = depGraphFact!.data;
    subt.same(
      depGraph.toJSON(),
      require(getFixture("analysis-results/yarn.json")),
      "returned dependency graph is the same",
    );
  });

  t.ok(pluginResult.scanResults[0].target, "os scan target is not falsy");
  t.same(
    pluginResult.scanResults[0].identity.args?.platform,
    "linux/amd64",
    "os scan result includes platform information",
  );
  t.same(
    pluginResult.scanResults[0].target,
    pluginResult.scanResults[1].target,
    "os scan target matches app scan target",
  );
  t.same(
    pluginResult.scanResults[1].target,
    pluginResult.scanResults[2].target,
    "app scans match their targets",
  );
});
