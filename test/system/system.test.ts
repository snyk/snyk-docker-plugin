import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import { DockerFileAnalysis } from "../../lib/dockerfile/types";
import * as subProcess from "../../lib/sub-process";
import { ManifestFile } from "../../lib/types";

const getDockerfileFixturePath = (folder) =>
  path.join(__dirname, "../fixtures/dockerfiles/library", folder, "Dockerfile");

test("inspect an image that does not exist and is not pullable", (t) => {
  return plugin.scan({ path: "not-here:latest" }).catch((err) => {
    t.same(err.message, "authentication required");
    t.pass("failed as expected");
  });
});

test("inspect an image with an unsupported pkg manager", async (t) => {
  const imgName = "archlinux/base@sha256";
  const imgTag =
    "42b6236b8f1b85a3bea6c8055f7e290f503440f722c9b4f82cc04bdcf3bcfcef";
  const img = imgName + ":" + imgTag;

  await dockerPull(t, img);
  const pluginResult = await plugin.scan({ path: img });
  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.same(depGraph.getDepPkgs(), [], "no dependencies should be found");
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "arch:unstable" }],
    "target operating system found",
  );
  t.same(
    pluginResult.scanResults[0].identity.type,
    "linux",
    "package manager linux",
  );
});

test("inspect a scratch image", async (t) => {
  const imgName = "busybox";
  const imgTag = "1.31.1";
  const img = imgName + ":" + imgTag;

  await dockerPull(t, img);
  const pluginResult = await plugin.scan({ path: img });
  const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  t.same(depGraph.getDepPkgs(), [], "no dependencies should be found");
  t.same(depGraph.pkgManager.repositories, [{ alias: "unknown:0.0" }]);
  t.same(
    pluginResult.scanResults[0].identity.type,
    "linux",
    "package manager linux",
  );
});

test("inspect node:6.14.2 - provider and regular pkg as same dependency", async (t) => {
  const imgName = "node";
  const imgTag = "6.14.2";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("node");

  await dockerPull(t, img);

  const pluginResponse = await plugin.scan({
    path: img,
    file: dockerFileLocation,
  });

  const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const imageId: string = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;

  t.equal(
    imageId,
    "00165cd5d0c00321af529a74915a9a7fe5cc9759ebca8e86ad38191933f551e8",
    "image id is correct",
  );
  t.equal(
    pluginResponse.scanResults[0].identity.type,
    "deb",
    "returns deb package manager",
  );
  t.equal(
    pluginResponse.scanResults[0].identity.type,
    depGraph.pkgManager.name,
    "scan result identity type and depGraph pkgManager name match",
  );

  const dockerfileAnalysis: DockerFileAnalysis = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "dockerfileAnalysis",
  )!.data;
  t.same(
    dockerfileAnalysis.baseImage,
    "buildpack-deps:stretch",
    "base image matches",
  );
  t.same(
    pluginResponse.scanResults[0].target.image,
    "docker-image|" + imgName,
    "target image matches",
  );
  t.same(depGraph.rootPkg.version, imgTag, "version matches");
  t.same(
    pluginResponse.scanResults[0].target.image,
    depGraph.rootPkg.name,
    "scan result target image and depGraph rootPkg name match",
  );
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "debian:8" }],
    "OS matches",
  );

  t.equal(
    depGraph.getPkgs().length,
    383,
    "expected number of total unique deps",
  );
});

test("inspect nginx:1.13.10", async (t) => {
  const imgName = "nginx";
  const imgTag = "1.13.10";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("nginx");

  await dockerPull(t, img);

  const pluginResponse = await plugin.scan({
    path: img,
    file: dockerFileLocation,
  });

  const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const imageId: string = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  const dockerfileAnalysis: DockerFileAnalysis = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "dockerfileAnalysis",
  )!.data;

  t.equal(
    imageId,
    "7f70b30f2cc66b5e23308fb20c6e57dc1ea0c47950cca797831b705177c6b8ce",
    "image id is correct",
  );
  t.equal(
    pluginResponse.scanResults[0].identity.type,
    "deb",
    "returns deb package manager",
  );

  t.same(
    dockerfileAnalysis.baseImage,
    "debian:stretch-slim",
    "base image matches",
  );
  t.same(
    pluginResponse.scanResults[0].target.image,
    "docker-image|" + imgName,
    "target image matches",
  );
  t.same(depGraph.rootPkg.version, imgTag, "version matches");
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "debian:9" }],
    "OS matches",
  );

  t.equal(
    depGraph.getPkgs().length,
    110,
    "expected number of total unique deps",
  );

  t.equal(
    Object.keys(dockerfileAnalysis.dockerfileLayers).length,
    1,
    "expected number of dockerfile layers",
  );

  const digest = Object.keys(dockerfileAnalysis.dockerfileLayers)[0];
  const instruction = Buffer.from(digest, "base64").toString();
  t.match(
    dockerfileAnalysis.dockerfileLayers,
    {
      [digest]: { instruction },
    },
    "dockerfile instruction digest points to the correct instruction",
  );
});

test("inspect redis:3.2.11-alpine", async (t) => {
  const imgName = "redis";
  const imgTag = "3.2.11-alpine";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("redis");

  await dockerPull(t, img);

  const pluginResponse = await plugin.scan({
    path: img,
    file: dockerFileLocation,
    globsToFind: {
      include: [
        "/etc/redhat-release*",
        "/etc/foo",
        "/nonexist/bar",
        "/etc/alpine-release",
      ],
      exclude: [],
    },
  });
  const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const imageId: string = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  const dockerfileAnalysis: DockerFileAnalysis = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "dockerfileAnalysis",
  )!.data;

  t.equal(
    imageId,
    "ca0b6709748d024a67c502558ea88dc8a1f8a858d380f5ddafa1504126a3b018",
    "image id is correct",
  );
  t.equal(
    pluginResponse.scanResults[0].identity.type,
    "apk",
    "returns apk package manager",
  );

  t.same(dockerfileAnalysis.baseImage, "alpine:3.7", "base image matches");
  t.same(
    pluginResponse.scanResults[0].target.image,
    "docker-image|" + imgName,
    "target image matches",
  );
  t.same(depGraph.rootPkg.version, imgTag, "version matches");
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "alpine:3.7.0" }],
    "OS matches",
  );

  t.equal(depGraph.getDepPkgs().length, 13, "expected number of deps");

  const manifestFiles: ManifestFile[] = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "imageManifestFiles",
  )!.data;
  t.ok(Array.isArray(manifestFiles), "manifest files data is an array");
  t.equals(manifestFiles.length, 1, "two manifest files found");

  const alpineRelease = manifestFiles.find(
    (match) => match.name === "alpine-release" && match.path === "/etc",
  );
  t.ok(alpineRelease !== undefined, "found alpine-release with full path");
});

test(
  "inspect image with hostname " + "localhost:5000/redis:3.2.11-alpine",
  async (t) => {
    const imgName = "redis";
    const imgTag = "3.2.11-alpine";
    const img = imgName + ":" + imgTag;
    const dockerFileLocation = getDockerfileFixturePath("redis");
    const hostAndImgName = "localhost:5000/" + imgName;
    const hostAndImg = hostAndImgName + ":" + imgTag;

    await dockerPull(t, img);
    await dockerTag(t, img, hostAndImg);

    const pluginResponse = await plugin.scan({
      path: hostAndImg,
      file: dockerFileLocation,
    });
    const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    const imageId: string = pluginResponse.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;
    const dockerfileAnalysis: DockerFileAnalysis = pluginResponse.scanResults[0].facts.find(
      (fact) => fact.type === "dockerfileAnalysis",
    )!.data;

    t.equal(
      imageId,
      "ca0b6709748d024a67c502558ea88dc8a1f8a858d380f5ddafa1504126a3b018",
      "image id is correct",
    );
    t.equal(
      pluginResponse.scanResults[0].identity.type,
      "apk",
      "returns apk package manager",
    );

    t.same(dockerfileAnalysis.baseImage, "alpine:3.7", "base image matches");
    t.same(
      pluginResponse.scanResults[0].target.image,
      "docker-image|" + hostAndImgName,
      "target image matches",
    );
    t.same(depGraph.rootPkg.version, imgTag, "version matches");
    t.same(
      pluginResponse.scanResults[0].target.image,
      depGraph.rootPkg.name,
      "scan result target image and depGraph rootPkg name match",
    );
    t.same(
      depGraph.pkgManager.repositories,
      [{ alias: "alpine:3.7.0" }],
      "OS matches",
    );
  },
);

test("inspect image with sha@256 " + "ubuntu@sha256", async (t) => {
  const imgName = "ubuntu";
  const imgSha =
    "@sha256:945039273a7b927869a07b375dc3148de16865de44dec8398672977e050a072e";
  const img = imgName + imgSha;

  await dockerPull(t, img);

  const pluginResponse = await plugin.scan({
    path: img,
  });
  const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const imageId: string = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;

  t.equal(
    imageId,
    "20bb25d32758db4f91b18a9581794cfaa6a8c5fbad80093e9a9e42211e131a48",
    "image id is correct",
  );
  t.equal(
    pluginResponse.scanResults[0].identity.type,
    "deb",
    "returns deb package manager",
  );

  t.same(
    pluginResponse.scanResults[0].target.image,
    "docker-image|" + imgName,
    "target image matches",
  );
  t.same(
    depGraph.rootPkg.version,
    undefined,
    "version is missing when hash is used as tag",
  );
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "ubuntu:18.04" }],
    "OS matches",
  );
});

test(
  "inspect image with hostname plus additional namespacing: " +
    "localhost:5000/redis:3.2.11-alpine",
  async (t) => {
    const imgName = "redis";
    const imgTag = "3.2.11-alpine";
    const img = imgName + ":" + imgTag;
    const dockerFileLocation = getDockerfileFixturePath("redis");
    const hostAndImgName = "localhost:5000/foo/" + imgName;
    const hostAndImg = hostAndImgName + ":" + imgTag;

    await dockerPull(t, img);
    await dockerTag(t, img, hostAndImg);

    const pluginResponse = await plugin.scan({
      path: hostAndImg,
      file: dockerFileLocation,
    });
    const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    const imageId: string = pluginResponse.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;

    t.equal(
      imageId,
      "ca0b6709748d024a67c502558ea88dc8a1f8a858d380f5ddafa1504126a3b018",
      "image id is correct",
    );
    t.equal(
      pluginResponse.scanResults[0].identity.type,
      "apk",
      "returns apk package manager",
    );

    t.same(
      pluginResponse.scanResults[0].target.image,
      "docker-image|" + hostAndImgName,
      "target image matches",
    );
    t.same(depGraph.rootPkg.version, imgTag, "version matches");
  },
);

test("inspect centos", async (t) => {
  const imgName = "centos";
  const imgTag = "7.4.1708";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("centos");

  await dockerPull(t, img);

  const pluginResponse = await plugin.scan({
    path: img,
    file: dockerFileLocation,
    globsToFind: {
      include: ["/etc/redhat-release", "/etc/foo"],
      exclude: [],
    },
  });
  const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "depGraph",
  )!.data;
  const imageId: string = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "imageId",
  )!.data;
  const dockerfileAnalysis: DockerFileAnalysis = pluginResponse.scanResults[0].facts.find(
    (fact) => fact.type === "dockerfileAnalysis",
  )!.data;

  t.equal(
    imageId,
    "9f266d35e02cc56fe11a70ecdbe918ea091d828736521c91dda4cc0c287856a9",
    "image id is correct",
  );
  t.equal(
    pluginResponse.scanResults[0].identity.type,
    "rpm",
    "returns rpm package manager",
  );

  t.same(dockerfileAnalysis.baseImage, "scratch", "base image matches");
  t.same(
    pluginResponse.scanResults[0].target.image,
    "docker-image|" + imgName,
    "target image matches",
  );
  t.same(depGraph.rootPkg.version, imgTag, "version matches");
  t.same(
    depGraph.pkgManager.repositories,
    [{ alias: "centos:7" }],
    "OS matches",
  );

  t.equal(depGraph.getDepPkgs().length, 145, "expected number of deps");
});

function dockerPull(t, name) {
  t.comment("pulling " + name);
  return subProcess.execute("docker", ["image", "pull", name]);
}

function dockerTag(t, fromName, toName) {
  t.comment("re-tagging " + fromName + " as " + toName);
  return subProcess.execute("docker", ["tag", fromName, toName]);
}
