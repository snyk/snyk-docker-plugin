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
      "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
    ],
    "Layers are read correctly",
  );
});

test("docker-archive image type throws on bad files", async (t) => {
  t.plan(2);

  const dockerfile = undefined;
  const pluginOptions = {
    experimental: true,
  };

  await t.rejects(
    async () =>
      await plugin.inspect(
        "docker-archive:missing-path",
        dockerfile,
        pluginOptions,
      ),
    Error("The provided docker archive path does not exist on the filesystem"),
    "throws when a file does not exists",
  );

  await t.rejects(
    async () =>
      await plugin.inspect("docker-archive:/tmp", dockerfile, pluginOptions),
    Error("The provided docker archive path is not a file"),
    "throws when the provided path is a directory",
  );
});
