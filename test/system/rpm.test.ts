import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { DockerFileAnalysis } from "../../lib/dockerfile/types";

function getFixture(fixturePath) {
  return path.join(__dirname, "../fixtures", fixturePath);
}

/**
 * The following bug proves that RPM packages do not have transitive dependencies.
 * This is a limitation in our RPM scanning currently, where we cannot produce a tree of dependencies.
 * More context here: https://snyk.slack.com/archives/CDSMEJ29E/p1592473698145800
 */
test("BUG: Dockerfile analysis does not produce transitive dependencies for RPM projects", async (t) => {
  const dockerfilePath = getFixture("dockerfiles/bug/Dockerfile");
  const fixturePath = getFixture("docker-archives/docker-save/bug.tar.gz");
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResult = await plugin.scan({
    path: imagePath,
    file: dockerfilePath,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const dockerfileAnalysis: DockerFileAnalysis = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "dockerfileAnalysis",
  )!.data;

  t.ok(
    depGraph.getDepPkgs().find((dep) => dep.name === "kernel-headers"),
    "dependency is found in dependency tree",
  );
  t.notOk(
    "kernel-headers" in dockerfileAnalysis.dockerfilePackages,
    "BUG: transitive dependency 'kernel-headers' not in 'dockerfilePackages'",
  );
});

test("scanning an rpm-based image produces the expected response", async (t) => {
  const fixturePath = getFixture("docker-archives/skopeo-copy/rpm.tar");
  const imagePath = `docker-archive:${fixturePath}`;

  const pluginResult = await plugin.scan({
    path: imagePath,
  });

  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const imageId: string = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "imageLayers",
  )!.data;
  t.same(
    imageId,
    "7f335821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
    "The image ID matches",
  );
  t.same(
    pluginResult.scanResults[0].identity.type,
    "rpm",
    "Correct package manager detected",
  );
  t.deepEqual(
    imageLayers,
    ["2943de48ac85f6eaeecbf35ed894375b5001e9001fd908e40d8e577b77e6bfeb.tar"],
    "Layers are read correctly",
  );

  t.same(
    depGraph.getDepPkgs().length,
    104,
    "Contains the expected number of dependencies",
  );
});
