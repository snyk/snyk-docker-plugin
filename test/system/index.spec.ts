import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";

import * as plugin from "../../lib";
import { DockerFileAnalysis } from "../../lib/dockerfile/types";
import * as subProcess from "../../lib/sub-process";
import { ManifestFile } from "../../lib/types";

function getDockerfileFixturePath(folder: string): string {
  return path.join(
    __dirname,
    "../fixtures/dockerfiles/library",
    folder,
    "Dockerfile",
  );
}

describe("system tests", () => {
  test("inspect an image that does not exist and is not pullable", async () => {
    await expect(() =>
      plugin.scan({ path: "not-here:latest" }),
    ).rejects.toThrowError("authentication required");
  });

  test("inspect an image with an unsupported pkg manager", async () => {
    const imgName = "archlinux/archlinux@sha256";
    const imgTag =
      "695e7fa35b2ea1846732a6c9f8cebec6c941a54d4aafd15a451062ef8be81bfb";
    const img = imgName + ":" + imgTag;

    await subProcess.execute("docker", [
      "image",
      "pull",
      img,
      "--platform",
      "linux/amd64",
    ]);

    const pluginResult = await plugin.scan({ path: img });
    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.getDepPkgs()).toEqual([]);
    expect(depGraph.pkgManager.repositories).toEqual([
      { alias: "arch:unstable" },
    ]);
    expect(pluginResult.scanResults[0].identity.type).toEqual("linux");
  });

  test("inspect node:6.14.2 - provider and regular pkg as same dependency", async () => {
    const imgName = "node";
    const imgTag = "6.14.2";
    const img = imgName + ":" + imgTag;
    const dockerFileLocation = getDockerfileFixturePath("node");

    await subProcess.execute("docker", [
      "image",
      "pull",
      img,
      "--platform",
      "linux/amd64",
    ]);

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

    expect(imageId).toEqual(
      "sha256:00165cd5d0c00321af529a74915a9a7fe5cc9759ebca8e86ad38191933f551e8",
    );
    expect(pluginResponse.scanResults[0].identity.type).toEqual("deb");
    expect(pluginResponse.scanResults[0].identity.type).toEqual(
      depGraph.pkgManager.name,
    );

    const dockerfileAnalysis: DockerFileAnalysis =
      pluginResponse.scanResults[0].facts.find(
        (fact) => fact.type === "dockerfileAnalysis",
      )!.data;
    expect(dockerfileAnalysis.baseImage).toEqual("buildpack-deps:stretch");
    expect(pluginResponse.scanResults[0].target.image).toEqual(
      "docker-image|" + imgName,
    );
    expect(depGraph.rootPkg.version).toEqual(imgTag);
    expect(pluginResponse.scanResults[0].target.image).toEqual(
      depGraph.rootPkg.name,
    );
    expect(depGraph.pkgManager.repositories).toEqual([{ alias: "debian:8" }]);

    expect(depGraph.getPkgs()).toHaveLength(383);
  });

  test("inspect nginx:1.13.10", async () => {
    const imgName = "nginx";
    const imgTag = "1.13.10";
    const img = imgName + ":" + imgTag;
    const dockerFileLocation = getDockerfileFixturePath("nginx");

    await subProcess.execute("docker", [
      "image",
      "pull",
      img,
      "--platform",
      "linux/amd64",
    ]);

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
    const dockerfileAnalysis: DockerFileAnalysis =
      pluginResponse.scanResults[0].facts.find(
        (fact) => fact.type === "dockerfileAnalysis",
      )!.data;

    expect(imageId).toEqual(
      "sha256:7f70b30f2cc66b5e23308fb20c6e57dc1ea0c47950cca797831b705177c6b8ce",
    );
    expect(pluginResponse.scanResults[0].identity.type).toEqual("deb");

    expect(dockerfileAnalysis.baseImage).toEqual("debian:stretch-slim");
    expect(pluginResponse.scanResults[0].target.image).toEqual(
      "docker-image|" + imgName,
    );
    expect(depGraph.rootPkg.version).toEqual(imgTag);
    expect(depGraph.pkgManager.repositories).toEqual([{ alias: "debian:9" }]);

    expect(depGraph.getPkgs()).toHaveLength(110);

    expect(Object.keys(dockerfileAnalysis.dockerfileLayers)).toHaveLength(1);

    const digest = Object.keys(dockerfileAnalysis.dockerfileLayers)[0];
    const instruction = Buffer.from(digest, "base64").toString();
    expect(dockerfileAnalysis.dockerfileLayers).toEqual({
      [digest]: { instruction },
    });
  });

  test("inspect redis:3.2.11-alpine", async () => {
    const imgName = "redis";
    const imgTag = "3.2.11-alpine";
    const img = imgName + ":" + imgTag;
    const dockerFileLocation = getDockerfileFixturePath("redis");

    await subProcess.execute("docker", [
      "image",
      "pull",
      img,
      "--platform",
      "linux/amd64",
    ]);

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
    const dockerfileAnalysis: DockerFileAnalysis =
      pluginResponse.scanResults[0].facts.find(
        (fact) => fact.type === "dockerfileAnalysis",
      )!.data;

    expect(imageId).toEqual(
      "sha256:ca0b6709748d024a67c502558ea88dc8a1f8a858d380f5ddafa1504126a3b018",
    );
    expect(pluginResponse.scanResults[0].identity.type).toEqual("apk");

    expect(dockerfileAnalysis.baseImage).toEqual("alpine:3.7");
    expect(pluginResponse.scanResults[0].target.image).toEqual(
      "docker-image|" + imgName,
    );
    expect(depGraph.rootPkg.version).toEqual(imgTag);
    expect(depGraph.pkgManager.repositories).toEqual([
      { alias: "alpine:3.7.0" },
    ]);

    expect(depGraph.getDepPkgs()).toHaveLength(13);

    const manifestFiles: ManifestFile[] =
      pluginResponse.scanResults[0].facts.find(
        (fact) => fact.type === "imageManifestFiles",
      )!.data;
    expect(Array.isArray(manifestFiles)).toBeTruthy();
    expect(manifestFiles).toHaveLength(1);

    const alpineRelease = manifestFiles.find(
      (match) => match.name === "alpine-release" && match.path === "/etc",
    );
    expect(alpineRelease).toBeDefined();
  });

  test(
    "inspect image with hostname " + "localhost:5000/redis:3.2.11-alpine",
    async () => {
      const imgName = "redis";
      const imgTag = "3.2.11-alpine";
      const img = imgName + ":" + imgTag;
      const dockerFileLocation = getDockerfileFixturePath("redis");
      const hostAndImgName = "localhost:5000/" + imgName;
      const hostAndImg = hostAndImgName + ":" + imgTag;

      await subProcess.execute("docker", [
        "image",
        "pull",
        img,
        "--platform",
        "linux/amd64",
      ]);
      await subProcess.execute("docker", ["tag", img, hostAndImg]);

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
      const dockerfileAnalysis: DockerFileAnalysis =
        pluginResponse.scanResults[0].facts.find(
          (fact) => fact.type === "dockerfileAnalysis",
        )!.data;

      expect(imageId).toEqual(
        "sha256:ca0b6709748d024a67c502558ea88dc8a1f8a858d380f5ddafa1504126a3b018",
      );
      expect(pluginResponse.scanResults[0].identity.type).toEqual("apk");

      expect(dockerfileAnalysis.baseImage).toEqual("alpine:3.7");
      expect(pluginResponse.scanResults[0].target.image).toEqual(
        "docker-image|" + hostAndImgName,
      );
      expect(depGraph.rootPkg.version).toEqual(imgTag);
      expect(pluginResponse.scanResults[0].target.image).toEqual(
        depGraph.rootPkg.name,
      );
      expect(depGraph.pkgManager.repositories).toEqual([
        { alias: "alpine:3.7.0" },
      ]);
    },
  );

  test("inspect image with sha@256 " + "ubuntu@sha256", async () => {
    const imgName = "ubuntu";
    const imgSha =
      "@sha256:eb5d7eda6804359e4fc5223a31a2d9caa4c8ea590b14060d81c8bc05b22ca04e";
    const img = imgName + imgSha;

    await subProcess.execute("docker", ["image", "pull", img]);

    const pluginResponse = await plugin.scan({
      path: img,
    });
    const depGraph: DepGraph = pluginResponse.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    const imageId: string = pluginResponse.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;

    expect(imageId).toEqual(
      "sha256:20bb25d32758db4f91b18a9581794cfaa6a8c5fbad80093e9a9e42211e131a48",
    );
    expect(pluginResponse.scanResults[0].identity.type).toEqual("deb");

    expect(pluginResponse.scanResults[0].target.image).toEqual(
      "docker-image|" + imgName,
    );
    expect(depGraph.rootPkg.version).toBeUndefined();
    expect(depGraph.pkgManager.repositories).toEqual([
      { alias: "ubuntu:18.04" },
    ]);
  });

  test(
    "inspect image with hostname plus additional namespacing: " +
      "localhost:5000/redis:3.2.11-alpine",
    async () => {
      const imgName = "redis";
      const imgTag = "3.2.11-alpine";
      const img = imgName + ":" + imgTag;
      const dockerFileLocation = getDockerfileFixturePath("redis");
      const hostAndImgName = "localhost:5000/foo/" + imgName;
      const hostAndImg = hostAndImgName + ":" + imgTag;

      await subProcess.execute("docker", [
        "image",
        "pull",
        img,
        "--platform",
        "linux/amd64",
      ]);
      await subProcess.execute("docker", ["tag", img, hostAndImg]);

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

      expect(imageId).toEqual(
        "sha256:ca0b6709748d024a67c502558ea88dc8a1f8a858d380f5ddafa1504126a3b018",
      );
      expect(pluginResponse.scanResults[0].identity.type).toEqual("apk");

      expect(pluginResponse.scanResults[0].target.image).toEqual(
        "docker-image|" + hostAndImgName,
      );
      expect(depGraph.rootPkg.version).toEqual(imgTag);
    },
  );
});
