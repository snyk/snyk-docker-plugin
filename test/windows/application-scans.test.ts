import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { ImageType } from "../../lib/types";

function getFixture(fixturePath: string): string {
  return path.join(__dirname, "../fixtures", fixturePath);
}

test("scanning a container image with 2 applications", async (t) => {
  const imageNameAndTag = "amazonlinux:2";
  const dockerfile = undefined;

  const staticAnalysisOptions = {
    imagePath: getFixture("docker-archives/skopeo-copy/rpm-npm-yarn.tar"),
    imageType: ImageType.DockerArchive,
    appScan: true,
  };

  const pluginResult = await plugin.inspect(imageNameAndTag, dockerfile, {
    staticAnalysisOptions,
  });

  t.ok(
    "scannedProjects" in pluginResult &&
      Array.isArray(pluginResult.scannedProjects),
    "scannedProjects is in plugin response and has the correct type",
  );
  t.same(pluginResult.scannedProjects.length, 3, "contains 3 scan results");

  const npmScan = pluginResult.scannedProjects[1];
  await t.test("first scanned project is scanned correctly", async (subt) => {
    subt.same(
      npmScan.packageManager,
      "npm",
      "npm as package manager is scanned correctly",
    );
    subt.same(
      npmScan.targetFile,
      path.normalize("/srv/npm-app/package.json"),
      "path to targetFile is correct",
    );
    subt.same(
      npmScan.depTree,
      require(getFixture("analysis-results/npm.json")),
      "returned dependency tree is the same",
    );
  });

  const yarnScan = pluginResult.scannedProjects[2];
  await t.test("second scanned project is scanned correctly", async (subt) => {
    subt.same(
      yarnScan.packageManager,
      "yarn",
      "yarn as package manager is scanned correctly",
    );
    subt.same(
      yarnScan.targetFile,
      path.normalize("/srv/yarn-app/package.json"),
      "path to targetFile is correct",
    );
    subt.same(
      yarnScan.depTree,
      require(getFixture("analysis-results/yarn.json")),
      "returned dependency tree is the same",
    );
  });

  t.ok(pluginResult.scannedProjects[0].meta, "os scan meta is not falsy");
  t.same(
    pluginResult.scannedProjects[0].meta,
    pluginResult.scannedProjects[1].meta,
    "os scan meta and app meta are identical",
  );
  t.same(
    pluginResult.scannedProjects[1].meta,
    pluginResult.scannedProjects[2].meta,
    "both applications meta is identical",
  );
});
