import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { ImageType } from "../../lib/types";

function getFixture(fixturePath): string {
  return path.join(__dirname, "../fixtures/docker-archives", fixturePath);
}

test("scanning an rpm-based image produces the expected response", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "amazonlinux:2";
  const dockerfile = undefined;
  const pluginOptions = {
    staticAnalysisOptions: {
      imagePath: getFixture("skopeo-copy/rpm.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResult = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptions,
  );

  t.ok(
    "manifestFiles" in pluginResult &&
      "package" in pluginResult &&
      "plugin" in pluginResult &&
      "hashes" in pluginResult,
    "Has the expected result properties",
  );

  t.deepEqual(pluginResult.manifestFiles, [], "Empty manifest files");
  t.same(
    pluginResult.plugin.dockerImageId,
    "cd2d92bc1c0c25b0e15c00cfaa44320d84af71ab3fe97280d53a7b769cd96c19",
    "The image ID matches",
  );
  t.same(
    pluginResult.plugin.packageManager,
    "rpm",
    "Correct package manager detected",
  );
  t.deepEqual(
    pluginResult.plugin.imageLayers,
    ["8a14b09953616e7e30d647996c12da4228e63fc93c59d04a060db6f5eb0074f4.tar"],
    "Layers are read correctly",
  );

  const dependencies = Object.keys(pluginResult.package.dependencies);
  t.same(
    dependencies.length,
    104,
    "Contains the expected number of dependencies",
  );
});
