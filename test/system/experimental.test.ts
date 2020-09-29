import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";

function getFixture(fixturePath): string {
  return path.join(__dirname, "../fixtures", fixturePath);
}

test("docker-archive image type can be scanned", async (t) => {
  const fixturePath = getFixture("docker-archives/docker-save/nginx.tar");
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
  t.same(
    pluginResult.scannedProjects[0].meta.platform,
    "linux/amd64",
    "Correct platform detected",
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

test("oci-archive image type can be scanned", async (t) => {
  const fixturePath = getFixture("oci-archives/alpine-3.12.0.tar");
  const imageNameAndTag = `oci-archive:${fixturePath}`;

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
    "docker-image|alpine-3.12.0.tar",
    "Image name matches",
  );
  t.same(
    pluginResult.scannedProjects[0].depTree.version,
    "",
    "Version must be empty",
  );
  t.same(
    pluginResult.plugin.dockerImageId,
    "sha256:0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b",
    "The image ID matches",
  );
  t.same(
    pluginResult.plugin.packageManager,
    "apk",
    "Correct package manager detected",
  );
  t.ok(
    pluginResult.scannedProjects[0].depTree.dependencies &&
      "alpine-keys/alpine-keys" in
        pluginResult.scannedProjects[0].depTree.dependencies,
    "Contains some expected dependency",
  );
  t.deepEqual(
    pluginResult.plugin.imageLayers,
    [
      path.normalize(
        "sha256:df20fa9351a15782c64e6dddb2d4a6f50bf6d3688060a34c4014b0d9a752eb4c",
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
  t.same(
    pluginResult.scannedProjects[0].meta.platform,
    "linux/amd64",
    "Correct platform detected",
  );
});

test("scanning a container with 2 applications (--app-vulns)", async (t) => {
  const imageNameAndTag = "snykgoof/os-app:node-snykin";
  const dockerfile = undefined;

  const pluginOptions = {
    experimental: true,
    docker: true,
    "app-vulns": true,
  };

  const pluginResult = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptions,
  );

  t.ok(
    "scannedProjects" in pluginResult &&
      Array.isArray(pluginResult.scannedProjects),
    "scannedProjects is in plugin response and has the correct type",
  );
  t.same(pluginResult.scannedProjects.length, 3, "contains 3 scan results");

  const osScan = pluginResult.scannedProjects[0];
  t.ok(osScan.meta, "os scan meta is not falsy");
  t.same(
    osScan.meta.platform,
    "linux/amd64",
    "os scan meta includes platform information",
  );

  const yarnScan = pluginResult.scannedProjects[1];
  await t.test("first scanned project is scanned correctly", async (subt) => {
    subt.same(
      yarnScan.packageManager,
      "yarn",
      "yarn as package manager is scanned correctly",
    );
    subt.same(
      yarnScan.targetFile,
      "/app2/package.json",
      "path to targetFile is correct",
    );
  });

  const npmScan = pluginResult.scannedProjects[2];
  await t.test("second scanned project is scanned correctly", async (subt) => {
    subt.same(
      npmScan.packageManager,
      "npm",
      "yarn as package manager is scanned correctly",
    );
    subt.same(
      npmScan.targetFile,
      "/app1/package.json",
      "path to targetFile is correct",
    );
  });
});

test("scanning a container with 0 applications (--app-vulns=false)", async (t) => {
  const imageNameAndTag = "snykgoof/os-app:node-snykin";
  const dockerfile = undefined;

  const pluginOptions = {
    experimental: true,
    docker: true,
    "app-vulns": "false",
  };

  const pluginResult = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptions,
  );

  t.ok(
    "scannedProjects" in pluginResult &&
      Array.isArray(pluginResult.scannedProjects),
    "scannedProjects is in plugin response and has the correct type",
  );
  t.same(pluginResult.scannedProjects.length, 1, "contains 1 scan results");

  const osScan = pluginResult.scannedProjects[0];
  t.ok(osScan.meta, "os scan meta is not falsy");
  t.same(
    osScan.meta.platform,
    "linux/amd64",
    "os scan meta includes platform information",
  );
});

test("scanning a container with 2 applications (--app-vulns=true)", async (t) => {
  const imageNameAndTag = "snykgoof/os-app:node-snykin";
  const dockerfile = undefined;

  const pluginOptions = {
    experimental: true,
    docker: true,
    "app-vulns": "true",
  };

  const pluginResult = await plugin.inspect(
    imageNameAndTag,
    dockerfile,
    pluginOptions,
  );

  t.ok(
    "scannedProjects" in pluginResult &&
      Array.isArray(pluginResult.scannedProjects),
    "scannedProjects is in plugin response and has the correct type",
  );
  t.same(pluginResult.scannedProjects.length, 3, "contains 3 scan results");

  const osScan = pluginResult.scannedProjects[0];
  t.ok(osScan.meta, "os scan meta is not falsy");
  t.same(
    osScan.meta.platform,
    "linux/amd64",
    "os scan meta includes platform information",
  );

  const yarnScan = pluginResult.scannedProjects[1];
  await t.test("first scanned project is scanned correctly", async (subt) => {
    subt.same(
      yarnScan.packageManager,
      "yarn",
      "yarn as package manager is scanned correctly",
    );
    subt.same(
      yarnScan.targetFile,
      "/app2/package.json",
      "path to targetFile is correct",
    );
  });

  const npmScan = pluginResult.scannedProjects[2];
  await t.test("second scanned project is scanned correctly", async (subt) => {
    subt.same(
      npmScan.packageManager,
      "npm",
      "yarn as package manager is scanned correctly",
    );
    subt.same(
      npmScan.targetFile,
      "/app1/package.json",
      "path to targetFile is correct",
    );
  });
});
