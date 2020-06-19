import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { DepTree, ImageType } from "../../lib/types";

function getFixture(fixturePath) {
  return path.join(__dirname, "../fixtures", fixturePath);
}

/**
 * The following bug proves that RPM packages do not have transitive dependencies.
 * This is a limitation in our RPM scanning currently, where we cannot produce a tree of dependencies.
 * More context here: https://snyk.slack.com/archives/CDSMEJ29E/p1592473698145800
 */
test("BUG: Dockerfile analysis does not produce transitive dependencies for RPM projects", async (t) => {
  const thisIsJustAnImageIdentifier = "bug:bug";
  const dockerfilePath = getFixture("dockerfiles/bug/Dockerfile");
  const pluginOptions = {
    staticAnalysisOptions: {
      imagePath: getFixture("docker-archives/docker-save/bug.tar.gz"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResult = await plugin.inspect(
    thisIsJustAnImageIdentifier,
    dockerfilePath,
    pluginOptions,
  );

  const results = pluginResult.scannedProjects;
  const osScanResult = results.find((res) => "docker" in res.depTree)!;
  const depTree = osScanResult.depTree as DepTree;
  const dockerResult = depTree.docker;

  t.same(depTree.packageFormatVersion, "rpm:0.0.1", "RPM project detected");
  t.ok(
    "kernel-headers" in depTree.dependencies,
    "dependency is found in dependency tree",
  );
  t.notOk(
    "kernel-headers" in dockerResult.dockerfilePackages,
    "BUG: transitive dependency 'kernel-headers' not in 'dockerfilePackages'",
  );
});

test("scanning an rpm-based image produces the expected response", async (t) => {
  const thisIsJustAnImageIdentifierInStaticAnalysis = "amazonlinux:2";
  const dockerfile = undefined;
  const pluginOptions = {
    staticAnalysisOptions: {
      imagePath: getFixture("docker-archives/skopeo-copy/rpm.tar"),
      imageType: ImageType.DockerArchive,
    },
  };

  const pluginResult = await plugin.inspect(
    thisIsJustAnImageIdentifierInStaticAnalysis,
    dockerfile,
    pluginOptions,
  );

  t.same(
    pluginResult.plugin.dockerImageId,
    "7f335821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
    "The image ID matches",
  );
  t.same(
    pluginResult.plugin.packageManager,
    "rpm",
    "Correct package manager detected",
  );
  t.deepEqual(
    pluginResult.plugin.imageLayers,
    ["2943de48ac85f6eaeecbf35ed894375b5001e9001fd908e40d8e577b77e6bfeb.tar"],
    "Layers are read correctly",
  );

  const dependencies = Object.keys(
    pluginResult.scannedProjects[0].depTree.dependencies,
  );
  t.same(
    dependencies.length,
    104,
    "Contains the expected number of dependencies",
  );
});
