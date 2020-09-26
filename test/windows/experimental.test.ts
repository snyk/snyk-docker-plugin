import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";

function getFixture(fixturePath): string {
  return path.join(__dirname, "../fixtures", fixturePath);
}

test("docker-archive image type can be scanned", async (t) => {
  const fixturePath = getFixture("docker-archives/docker-save/nginx.tar");
  const imageNameAndTag = `docker-archive:${fixturePath}`;

  const pluginResult = await plugin.scan({
    path: imageNameAndTag,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.same(depGraph.rootPkg.name, "docker-image|nginx.tar", "Image name matches");
  t.same(depGraph.rootPkg.version, undefined, "Version must be missing");

  const imageId: string = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  t.same(
    imageId,
    "5a3221f0137beb960c34b9cf4455424b6210160fd618c5e79401a07d6e5a2ced",
    "The image ID matches",
  );
  t.same(
    pluginResult.scanResults[0].identity.type,
    "deb",
    "Correct package manager detected",
  );
  t.ok(
    depGraph.getDepPkgs().find((dep) => dep.name === "adduser"),
    "Contains some expected dependency",
  );

  const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageLayers",
  )!.data;
  t.deepEqual(
    imageLayers,
    [
      path.normalize(
        "ac415f8e415b242117277e7ee5224b30389698b46101e0f28224490af3b90a9d/layer.tar",
      ),
    ],
    "Layers are read correctly",
  );
  t.same(
    pluginResult.scanResults[0].identity.args?.platform,
    "linux/amd64",
    "Correct platform detected",
  );
});

test("oci-archive image type can be scanned", async (t) => {
  const fixturePath = getFixture("oci-archives/alpine-3.12.0.tar");
  const imageNameAndTag = `oci-archive:${fixturePath}`;

  const pluginResult = await plugin.scan({
    path: imageNameAndTag,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.same(
    depGraph.rootPkg.name,
    "docker-image|alpine-3.12.0.tar",
    "Image name matches",
  );
  t.same(depGraph.rootPkg.version, undefined, "Version must be missing");
  const imageId: string = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  t.same(
    imageId,
    "sha256:0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b",
    "The image ID matches",
  );
  t.same(
    pluginResult.scanResults[0].identity.type,
    "apk",
    "Correct package manager detected",
  );
  t.ok(
    depGraph.getDepPkgs().find((dep) => dep.name === "alpine-keys/alpine-keys"),
    "Contains some expected dependency",
  );
  const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageLayers",
  )!.data;
  t.deepEqual(
    imageLayers,
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

  const pluginResult = await plugin.scan({
    path: imageNameAndTag,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.same(depGraph.rootPkg.name, "docker-image|nginx", "Image name matches");
  t.same(depGraph.rootPkg.version, "1.19.0", "Version must not be empty");
  const imageId: string = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  t.same(
    imageId,
    "2622e6cca7ebbb6e310743abce3fc47335393e79171b9d76ba9d4f446ce7b163",
    "The image ID matches",
  );
  t.same(
    pluginResult.scanResults[0].identity.type,
    "deb",
    "Correct package manager detected",
  );
  t.ok(
    depGraph.getDepPkgs().find((dep) => dep.name === "nginx"),
    "Contains some expected dependency",
  );
  const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageLayers",
  )!.data;
  t.same(imageLayers.length, 5, "Returns expected number of layers");
  t.ok(
    imageLayers.every((layer) => layer.endsWith("layer.tar")),
    "Every found layer has the correct name",
  );
  t.same(
    pluginResult.scanResults[0].identity.args?.platform,
    "linux/amd64",
    "Correct platform detected",
  );
});
