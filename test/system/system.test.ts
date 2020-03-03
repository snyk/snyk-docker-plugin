#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as path from "path";
import { test } from "tap";

import * as plugin from "../../lib";
import * as subProcess from "../../lib/sub-process";

const getDockerfileFixturePath = (folder) =>
  path.join(__dirname, "../fixtures/dockerfiles/library", folder, "Dockerfile");

test("attempt to connect to non-existent host", (t) => {
  const host = "does-not-exist:1234";
  const options = { host };

  const imgName = "nginx";
  const imgTag = "1.13.10";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("nginx");

  return dockerPull(t, img)
    .then(() => {
      return dockerGetImageId(t, img);
    })
    .then((_) => {
      return plugin.inspect(img, dockerFileLocation, options);
    })
    .then(() => {
      t.fail("should have failed");
    })
    .catch((err) => {
      t.includes(err.message, "no such host");
    });
});

test("inspect an image that does not exist and is not pullable", (t) => {
  return plugin.inspect("not-here:latest").catch((err) => {
    t.same(
      err.message,
      "Docker error: image was not found locally and pulling failed: not-here:latest",
    );
    t.pass("failed as expected");
  });
});

test("inspect an image with an unsupported pkg manager", async (t) => {
  const imgName = "archlinux/base@sha256";
  const imgTag =
    "42b6236b8f1b85a3bea6c8055f7e290f503440f722c9b4f82cc04bdcf3bcfcef";
  const img = imgName + ":" + imgTag;

  await dockerPull(t, img);
  const pluginResult = await plugin.inspect(img);
  t.same(pluginResult.manifestFiles, [], "no manifest files should found");
  t.same(
    pluginResult.package.dependencies,
    {},
    "no dependencies should be found",
  );
  t.same(
    pluginResult.package.targetOS,
    { name: "arch", version: "unstable" },
    "target operating system found",
  );
  t.same(
    pluginResult.package.packageFormatVersion,
    "linux:0.0.1",
    "package manager linux",
  );
  t.same(pluginResult.plugin.packageManager, "linux", "package manager linux");
});

test("inspect a scratch image", async (t) => {
  const imgName = "busybox";
  const imgTag = "1.31.1";
  const img = imgName + ":" + imgTag;

  await dockerPull(t, img);
  const pluginResult = await plugin.inspect(img);
  t.same(pluginResult.manifestFiles, [], "no manifest files should found");
  t.same(
    pluginResult.package.dependencies,
    {},
    "no dependencies should be found",
  );
  t.same(
    pluginResult.package.targetOS,
    { name: "unknown", version: "0.0" },
    "target operating system found",
  );
  t.same(
    pluginResult.package.packageFormatVersion,
    "linux:0.0.1",
    "package manager linux",
  );
  t.same(pluginResult.plugin.packageManager, "linux", "package manager linux");
});

test("inspect node:6.14.2 - provider and regular pkg as same dependency", (t) => {
  const imgName = "node";
  const imgTag = "6.14.2";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("node");

  let expectedImageId;
  return dockerPull(t, img)
    .then(() => {
      return dockerGetImageId(t, img);
    })
    .then((imageId) => {
      expectedImageId = imageId;
      return plugin.inspect(img, dockerFileLocation);
    })
    .then((res) => {
      const plugin = res.plugin;
      const pkg = res.package;
      const uniquePkgs = uniquePkgSpecs(pkg);

      t.equal(plugin.name, "snyk-docker-plugin", "name");
      t.equal(
        plugin.dockerImageId,
        expectedImageId,
        "image id is correct: " + plugin.dockerImageId,
      );
      t.equal(plugin.packageManager, "deb", "returns deb package manager");

      t.match(
        pkg,
        {
          name: "docker-image|" + imgName,
          version: imgTag,
          packageFormatVersion: "deb:0.0.1",
          targetOS: {
            name: "debian",
            version: "8",
          },
          docker: {
            baseImage: "buildpack-deps:stretch",
          },
        },
        "root pkg",
      );

      t.equal(uniquePkgs.length, 383, "expected number of total unique deps");

      const deps = pkg.dependencies;
      // Note: this test is now a bit fragile due to dep-tree-pruning
      t.equal(Object.keys(deps).length, 105, "expected number of direct deps");
      t.match(
        deps,
        {
          libtool: {
            version: "2.4.2-1.11",
            dependencies: {
              "gcc-defaults/gcc": {
                version: "4:4.9.2-2",
                dependencies: {
                  "gcc-4.9": {
                    version: "4.9.2-10+deb8u1",
                    dependencies: {
                      "gcc-4.9/libgcc-4.9-dev": {
                        version: "4.9.2-10+deb8u1",
                        dependencies: {
                          "gcc-4.9/libitm1": {
                            version: "4.9.2-10+deb8u1",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "regular deps seem ok",
      );

      const commonDeps = deps["meta-common-packages"].dependencies;
      t.equal(
        Object.keys(commonDeps).length,
        73,
        "expected number of common deps under meta pkg",
      );

      t.match(
        commonDeps,
        {
          "gcc-4.9/gcc-4.9-base": {
            name: "gcc-4.9/gcc-4.9-base",
            version: "4.9.2-10+deb8u1",
          },
          "glibc/libc6": {
            name: "glibc/libc6",
            version: "2.19-18+deb8u10",
          },
        },
        "meta-common-packages seems fine",
      );
    });
});

test("inspect nginx:1.13.10", (t) => {
  const imgName = "nginx";
  const imgTag = "1.13.10";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("nginx");

  let expectedImageId;
  return dockerPull(t, img)
    .then(() => {
      return dockerGetImageId(t, img);
    })
    .then((imageId) => {
      expectedImageId = imageId;
      return plugin.inspect(img, dockerFileLocation);
    })
    .then((res) => {
      const plugin = res.plugin;
      const pkg = res.package;

      t.equal(plugin.name, "snyk-docker-plugin", "name");
      t.equal(
        plugin.dockerImageId,
        expectedImageId,
        "image id is correct: " + plugin.dockerImageId,
      );
      t.equal(plugin.packageManager, "deb", "returns deb package manager");

      t.match(
        pkg,
        {
          name: "docker-image|" + imgName,
          version: imgTag,
          packageFormatVersion: "deb:0.0.1",
          targetOS: {
            name: "debian",
            version: "9",
          },
          docker: {
            baseImage: "debian:stretch-slim",
          },
        },
        "root pkg",
      );

      t.equal(
        uniquePkgSpecs(pkg).length,
        110,
        "expected number of total unique deps",
      );

      const deps = pkg.dependencies;
      // Note: this test is now a bit fragile due to dep-tree-pruning
      t.equal(Object.keys(deps).length, 48, "expected number of direct deps");
      t.match(
        deps,
        {
          "nginx-module-njs": {
            version: "1.13.10.0.1.15-1~stretch",
            dependencies: {
              nginx: {
                version: "1.13.10-1~stretch",
                dependencies: {
                  adduser: {
                    name: "adduser",
                    version: "3.115",
                  },
                  "openssl/libssl1.1": {
                    name: "openssl/libssl1.1",
                    version: "1.1.0f-3+deb9u1",
                  },
                  "lsb/lsb-base": {
                    version: "9.20161125",
                  },
                },
              },
            },
          },
          "nginx-module-xslt": {
            name: "nginx-module-xslt",
            version: "1.13.10-1~stretch",
            dependencies: {
              libxml2: {
                version: "2.9.4+dfsg1-2.2+deb9u2",
              },
              nginx: {
                version: "1.13.10-1~stretch",
              },
            },
          },
          "gettext/gettext-base": {
            version: "0.19.8.1-2",
          },
          "shadow/login": {
            // a package marked as "Auto-Installed", but not dependant upon:
            name: "shadow/login",
            version: "1:4.4-4.1",
            dependencies: {
              "pam/libpam-runtime": {
                version: "1.1.8-3.6",
              },
            },
          },
        },
        "regular deps seem ok",
      );

      t.false(
        deps["nginx-module-xslt"].dependencies.nginx.dependencies,
        "nginx-module-xslt -> ngxinx has do deps",
      );

      t.equal(
        Object.keys(pkg.docker.dockerfileLayers).length,
        1,
        "expected number of dockerfile layers",
      );

      const digest = Object.keys(pkg.docker.dockerfileLayers)[0];
      const instruction = Buffer.from(digest, "base64").toString();
      t.match(
        pkg.docker.dockerfileLayers,
        {
          [digest]: { instruction },
        },
        "dockerfile instruction digest points to the correct instruction",
      );

      const commonDeps = deps["meta-common-packages"].dependencies;
      t.equal(
        Object.keys(commonDeps).length,
        19,
        "expected number of common deps under meta pkg",
      );

      t.match(
        commonDeps,
        {
          "zlib/zlib1g": {
            name: "zlib/zlib1g",
            version: "1:1.2.8.dfsg-5",
          },
          debconf: {
            version: "1.5.61",
          },
          dpkg: {
            version: "1.18.24",
          },
        },
        "meta-common-packages seems fine",
      );
    });
});

test("inspect redis:3.2.11-alpine", (t) => {
  const imgName = "redis";
  const imgTag = "3.2.11-alpine";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("redis");

  let expectedImageId;
  return dockerPull(t, img)
    .then(() => {
      return dockerGetImageId(t, img);
    })
    .then((imageId) => {
      expectedImageId = imageId;
      return plugin.inspect(img, dockerFileLocation, {
        manifestGlobs: ["/etc/redhat-release*", "/etc/foo", "/nonexist/bar"],
      });
    })
    .then((res) => {
      const plugin = res.plugin;
      const pkg = res.package;
      const manifest = res.manifestFiles;

      t.equal(plugin.name, "snyk-docker-plugin", "name");
      t.equal(
        plugin.dockerImageId,
        expectedImageId,
        "image id is correct: " + plugin.dockerImageId,
      );
      t.equal(plugin.packageManager, "apk", "returns apk package manager");

      t.match(
        pkg,
        {
          name: "docker-image|" + imgName,
          version: imgTag,
          packageFormatVersion: "apk:0.0.1",
          targetOS: {
            name: "alpine",
            version: "3.7.0",
          },
          docker: {
            baseImage: "alpine:3.7",
          },
        },
        "root pkg",
      );

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 13, "expected number of deps");
      t.match(
        deps,
        {
          busybox: {
            name: "busybox",
            version: "1.27.2-r7",
          },
          "libressl2.6-libcrypto": {
            name: "libressl2.6-libcrypto",
            version: "2.6.3-r0",
          },
          zlib: {
            name: "zlib",
            version: "1.2.11-r1",
          },
        },
        "deps",
      );
      t.match(manifest, [], "manifest files");
    });
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
    await dockerGetImageId(t, hostAndImg);
    const res = await plugin.inspect(hostAndImg, dockerFileLocation);

    t.match(
      res.package,
      {
        name: "docker-image|" + hostAndImgName,
        version: imgTag,
        packageFormatVersion: "apk:0.0.1",
        targetOS: {
          name: "alpine",
          version: "3.7.0",
        },
        docker: {
          baseImage: "alpine:3.7",
        },
      },
      "root pkg",
    );
  },
);

test("inspect image with sha@256 " + "ubuntu@sha256", async (t) => {
  const imgName = "ubuntu";
  const imgTag = "";
  const imgSha =
    "@sha256:945039273a7b927869a07b375dc3148de16865de44dec8398672977e050a072e";
  const img = imgName + imgSha;

  await dockerPull(t, img);
  await dockerGetImageId(t, img);
  const res = await plugin.inspect(img);

  t.match(
    res.package,
    {
      name: "docker-image|" + imgName,
      version: imgTag,
      packageFormatVersion: "deb:0.0.1",
      targetOS: {
        name: "ubuntu",
        version: "18.04",
      },
    },
    "root pkg",
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
    await dockerGetImageId(t, hostAndImg);
    const res = await plugin.inspect(hostAndImg, dockerFileLocation);

    t.match(
      res.package,
      {
        name: "docker-image|" + hostAndImgName,
        version: imgTag,
      },
      "root pkg",
    );
  },
);

test("inspect centos", (t) => {
  const imgName = "centos";
  const imgTag = "7.4.1708";
  const img = imgName + ":" + imgTag;
  const dockerFileLocation = getDockerfileFixturePath("centos");

  let expectedImageId;
  return dockerPull(t, img)
    .then(() => {
      return dockerGetImageId(t, img);
    })
    .then((imageId) => {
      expectedImageId = imageId;
      return plugin.inspect(img, dockerFileLocation, {
        manifestGlobs: ["/etc/redhat-release", "/etc/foo"],
      });
    })
    .then((res) => {
      const plugin = res.plugin;
      const pkg = res.package;
      const manifest = res.manifestFiles;

      t.equal(plugin.name, "snyk-docker-plugin", "name");
      t.equal(
        plugin.dockerImageId,
        expectedImageId,
        "image id is correct: " + plugin.dockerImageId,
      );
      t.equal(plugin.packageManager, "rpm", "returns rpm package manager");

      t.match(
        pkg,
        {
          name: "docker-image|" + imgName,
          version: imgTag,
          packageFormatVersion: "rpm:0.0.1",
          targetOS: {
            name: "centos",
            version: "7",
          },
          docker: {
            baseImage: "scratch",
          },
        },
        "root pkg",
      );

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 145, "expected number of deps");
      t.match(
        deps,
        {
          "openssl-libs": {
            name: "openssl-libs",
            version: "1:1.0.2k-8.el7",
          },
          passwd: {
            name: "passwd",
            version: "0.79-4.el7",
          },
          systemd: {
            name: "systemd",
            version: "219-42.el7",
          },
          dracut: {
            name: "dracut",
            version: "033-502.el7", // TODO: make sure we handle this well
          },
          iputils: {
            version: "20160308-10.el7",
          },
        },
        "deps",
      );

      t.match(
        manifest,
        [
          {
            name: "redhat-release",
            path: "/etc",
            contents: "Q2VudE9TIExpbnV4IHJlbGVhc2UgNy40LjE3MDggKENvcmUpIAo=",
          },
        ],
        "manifest files",
      );
    });
});

function dockerPull(t, name) {
  t.comment("pulling " + name);
  return subProcess.execute("docker", ["image", "pull", name]);
}

function dockerTag(t, fromName, toName) {
  t.comment("re-tagging " + fromName + " as " + toName);
  return subProcess.execute("docker", ["tag", fromName, toName]);
}

function dockerGetImageId(t, name) {
  return subProcess.execute("docker", ["inspect", name]).then((output) => {
    const inspection = JSON.parse(output.stdout);

    const id = inspection[0].Id;

    t.equal(
      id.length,
      "sha256:".length + 64,
      "image id from `docker inspect` looks like what we expect",
    );

    return id;
  });
}

function uniquePkgSpecs(tree) {
  const uniq: string[] = [];

  function scan(pkg: any) {
    const spec: string = pkg.name + "@" + pkg.version;
    if (uniq.indexOf(spec) === -1) {
      uniq.push(spec);
    }

    const deps = pkg.dependencies || {};
    for (const name of Object.keys(deps)) {
      scan(deps[name]);
    }
  }

  scan(tree);

  return uniq;
}
