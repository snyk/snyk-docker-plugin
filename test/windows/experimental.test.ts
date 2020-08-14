import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";

function getFixture(fixturePath): string {
  return path.join(__dirname, "../fixtures/docker-archives", fixturePath);
}

test("docker-archive image type can be scanned", async (t) => {
  const fixturePath = getFixture("docker-save/nginx.tar");
  const imageNameAndTag = `docker-archive:${fixturePath}`;

  const dockerfile = undefined;
  const pluginOptions = {
    experimental: true,
  };

  const pluginResult = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptions,
  );

  t.same(
    pluginResult.scannedProjects[0].depTree.name,
    "docker-image|nginx.tar",
    "Image name matches",
  );
  t.same(
    pluginResult.scannedProjects[0].depTree.version,
    "",
    "Version must be empty",
  );
  t.same(
    pluginResult.plugin.dockerImageId,
    "5a3221f0137beb960c34b9cf4455424b6210160fd618c5e79401a07d6e5a2ced",
    "The image ID matches",
  );
  t.same(
    pluginResult.plugin.packageManager,
    "deb",
    "Correct package manager detected",
  );
  t.ok(
    pluginResult.scannedProjects[0].depTree.dependencies &&
      "adduser" in pluginResult.scannedProjects[0].depTree.dependencies,
    "Contains some expected dependency",
  );
  t.deepEqual(
    pluginResult.plugin.imageLayers,
    [
      path.normalize(
        "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
      ),
    ],
    "Layers are read correctly",
  );
});

test("static scan for Identifier type image (nginx:1.19.0)", async (t) => {
  const imageNameAndTag = `nginx:1.19.0`;
  const dockerfile = undefined;
  const pluginOptions = {
    experimental: true,
  };

  const pluginResult = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptions,
  );

  t.same(
    pluginResult.scannedProjects[0].depTree.name,
    "docker-image|nginx",
    "Image name matches",
  );
  t.same(
    pluginResult.scannedProjects[0].depTree.version,
    "1.19.0",
    "Version must not be empty",
  );
  t.same(
    pluginResult.plugin.dockerImageId,
    "2622e6cca7ebbb6e310743abce3fc47335393e79171b9d76ba9d4f446ce7b163",
    "The image ID matches",
  );
  t.same(
    pluginResult.plugin.packageManager,
    "deb",
    "Correct package manager detected",
  );
  t.ok(
    pluginResult.scannedProjects[0].depTree.dependencies &&
      "nginx" in pluginResult.scannedProjects[0].depTree.dependencies,
    "Contains some expected dependency",
  );
  t.same(
    pluginResult.plugin.imageLayers.length,
    5,
    "Returns expected number of layers",
  );
  t.ok(
    pluginResult.plugin.imageLayers.every((layer) =>
      layer.endsWith("layer.tar"),
    ),
    "Every found layer has the correct name",
  );
});
