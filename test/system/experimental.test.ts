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
    Error("The provided archive path does not exist on the filesystem"),
    "throws when a file does not exists",
  );

  await t.rejects(
    async () =>
      await plugin.inspect("docker-archive:/tmp", dockerfile, pluginOptions),
    Error("The provided archive path is not a file"),
    "throws when the provided path is a directory",
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
  t.deepEqual(
    pluginResult.plugin.imageLayers,
    [
      "29a4ff5c2250ab72c60545ba67bd67d87daa05e4abd186e7d488d921287c893b/layer.tar",
      "bd0f0d2dba229cb9005123b54a646fe612882343c06b68c4722f221fdc597d82/layer.tar",
      "5a88377adcb6f00f0388d45a929fe1159916d7c9e733db78d6defb3fcd325a68/layer.tar",
      "94f68a38cdeff495ef63de6533b7d7486312ff7bc184120a620ad738536f548d/layer.tar",
      "44fc3f4af0d0f3587192b742d77b7c1c85cfd230bfb5474f6e1619da7962e3e3/layer.tar",
    ],
    "Layers are read correctly",
  );
});
