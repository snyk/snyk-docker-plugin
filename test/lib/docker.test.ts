#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { readFileSync } from "fs";
import * as fs from "fs";
import * as md5 from "md5";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";
import { pack as packFs } from "tar-fs";
import { pack as packStream, Pack as PackStream } from "tar-stream";

import * as apkAnalyzer from "../../lib/analyzer/apk-analyzer";
import * as aptAnalyzer from "../../lib/analyzer/apt-analyzer";
import * as osReleaseDetector from "../../lib/analyzer/os-release-detector";
import { Docker } from "../../lib/docker";
import { streamToBuffer } from "../../lib/stream-utils";
import * as subProcess from "../../lib/sub-process";

const getOsFixturePath = (...from) =>
  path.join(__dirname, "../fixtures/os", ...from);

const readOsFixtureFileIntoBuffer = (...from) =>
  fs.readFileSync(getOsFixturePath(...from), "utf8");

const readOsFixtureFileCalcMd5 = (...from) =>
  md5(readOsFixtureFileIntoBuffer(...from));

test("docker run", async (t) => {
  const stub = sinon.stub(subProcess, "execute");
  stub.resolves("text");
  t.beforeEach(async () => {
    stub.resetHistory();
  });
  t.tearDown(() => {
    stub.restore();
  });

  const targetImage = "some:image";
  const docker = new Docker(targetImage);

  t.test("no args", async (t) => {
    await docker.run("ls");
    const subProcessArgs = stub.getCall(0).args;
    t.same(
      subProcessArgs,
      [
        "docker",
        [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          targetImage,
          "ls",
        ],
      ],
      "args passed to subProcess.execute as expected",
    );
  });

  t.test("with args", async (t) => {
    await docker.run("ls", ["./dir", "-lah"]);
    const subProcessArgs = stub.getCall(0).args;
    t.same(
      subProcessArgs,
      [
        "docker",
        [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          targetImage,
          "ls",
          "./dir",
          "-lah",
        ],
      ],
      "args passed to subProcess.execute as expected",
    );
  });
});

test("safeCat", async (t) => {
  const stub = sinon.stub(subProcess, "execute");
  t.beforeEach(async () => {
    stub.resetHistory();
  });
  t.tearDown(() => {
    stub.restore();
  });

  const targetImage = "some:image";
  const docker = new Docker(targetImage);

  t.test("file found", async (t) => {
    stub.resolves({ stdout: "file contents" });
    const content = (await docker.catSafe("present.txt")).stdout;
    t.equal(content, "file contents", "file contents returned");
  });

  t.test("file not found", async (t) => {
    const error = "cat: absent.txt: No such file or directory";
    stub.callsFake(() => {
      throw { stderr: error };
    });
    const content = (await docker.catSafe("absent.txt")).stderr;
    t.equal(content, error, "error string returned");
  });

  t.test("unexpected error", async (t) => {
    stub.callsFake(() => {
      throw { stderr: "something went horribly wrong", stdout: "" };
    });
    await t.rejects(
      docker.catSafe("absent.txt"),
      { stderr: "something went horribly wrong", stdout: "" },
      "rejects with expected error",
    );
  });
});

test("safeLs", async (t) => {
  const stub = sinon.stub(subProcess, "execute");
  t.beforeEach(async () => {
    stub.resetHistory();
  });
  t.tearDown(() => {
    stub.restore();
  });

  const targetImage = "some:image";
  const docker = new Docker(targetImage);

  t.test("directory found", async (t) => {
    stub.resolves({
      stdout: ".\n..\n.dockerenv\nbin/\ndev/\netc/\nusr/\nvar/\n",
    });
    const content = (await docker.lsSafe("/")).stdout;
    t.equal(
      content,
      ".\n..\n.dockerenv\nbin/\ndev/\netc/\nusr/\nvar/\n",
      "directory listing returned",
    );
  });

  t.test("directory not found", async (t) => {
    const error = "ls: /abc: No such file or directory";
    stub.callsFake(() => {
      throw { stderr: error };
    });
    const content = (await docker.lsSafe("/abc")).stderr;
    t.equal(content, error, "error string returned");
  });

  t.test("command not found", async (t) => {
    const error = `>
      docker: Error response from daemon: OCI runtime create failed:
      container_linux.go:345: starting container process caused "exec: \"ls\":
      executable file not found in $PATH": unknown.`;
    stub.callsFake(() => {
      throw { stderr: error };
    });
    const content = (await docker.lsSafe("/")).stderr;
    t.equal(content, error, "error string returned");
  });

  t.test("unexpected error", async (t) => {
    stub.callsFake(() => {
      throw { stderr: "something went horribly wrong", stdout: "" };
    });
    await t.rejects(
      docker.lsSafe("/"),
      { stderr: "something went horribly wrong", stdout: "" },
      "rejects with expected error",
    );
  });
});

const getLSOutputFixture = (file: string) =>
  path.join(__dirname, "../fixtures/ls-output", file);

test("findGlobs", async (t) => {
  const stub = sinon.stub(subProcess, "execute");
  t.beforeEach(async () => {
    stub.resetHistory();
  });
  t.tearDown(() => {
    stub.restore();
  });

  const targetImage = "some:image";
  const docker = new Docker(targetImage);

  t.test("find globs in single directory", async (t) => {
    stub.resolves({
      stdout: "./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\nfile2.txt\n",
    });
    const files = await docker.findGlobs(["**/file?.*"], [], "/", false);
    t.same(files, ["/file1.txt", "/file2.txt"]);
  });

  t.test("find globs in a directory structure", async (t) => {
    stub.resolves({
      stdout:
        "/app:\n./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\nfile2.txt\n\n/app/dir1:" +
        "\n./\n../\ndir11/\nfile3.json\nfile4.txt\n\n/app/dir1/dir11:\n./\n../\n" +
        "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.json\n",
    });
    const files = await docker.findGlobs(["**/file?.json"]);
    t.same(files, ["/dir1/file3.json", "/dir3/file6.json"]);
  });

  const registryGlobs = [
    "**/package.json",
    "**/package-lock.json",
    "**/Gemfile",
    "**/Gemfile.lock",
    "**/yarn.lock",
    "**/pom.xml",
    "**/build.gradle",
    "**/build.sbt",
    "**/requirements.txt",
    "**/Gopkg.lock",
    "**/vendor.json",
    "**/packages.config",
    "**/*.csproj",
    "**/*.fsproj",
    "**/*.vbproj",
    "**/project.json",
    "**/project.assets.json",
    "**/composer.lock",
    "**/Dockerfile",
  ];

  t.test("find globs using registry globs", async (t) => {
    stub.resolves({
      stdout:
        "/app:\n./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\npom.xml\n\n/app/dir1:" +
        "\n./\n../\ndir11/\npackage.json\npackage-lock.json\n\n/app/dir1/dir11:\n./\n../\n" +
        "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.csproj\n",
    });
    const files = await docker.findGlobs(registryGlobs);
    t.same(files, [
      "/pom.xml",
      "/dir1/package.json",
      "/dir1/package-lock.json",
      "/dir3/file6.csproj",
    ]);
  });

  t.test("find globs using registry globs with exclude globs", async (t) => {
    stub.resolves({
      stdout:
        "/app:\n./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\npom.xml\n\n/app/dir1:" +
        "\n./\n../\ndir11/\npackage.json\npackage-lock.json\n\n/app/dir1/dir11:\n./\n../\n" +
        "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.csproj\n",
    });
    const files = await docker.findGlobs(registryGlobs, ["/dir1/*"]);
    t.same(files, ["/pom.xml", "/dir3/file6.csproj"]);
  });

  t.test(
    "find globs on ghost app using node_modules exclude glob",
    async (t) => {
      stub.resolves({
        stdout: readFileSync(getLSOutputFixture("ghost-app.txt")).toString(),
      });

      const files = await docker.findGlobs(
        ["**/package.json", "**/package-lock.json", "**/yarn.lock"],
        ["**/node_modules/**"],
      );

      t.same(files, [
        "/opt/yarn-v1.16.0/package.json",
        "/var/lib/ghost/versions/2.25.6/package.json",
        "/var/lib/ghost/versions/2.25.6/yarn.lock",
        "/var/lib/ghost/versions/2.25.6/content/themes/casper/package.json",
        "/var/lib/ghost/versions/2.25.6/content/themes/casper/yarn.lock",
      ]);
    },
  );

  t.test("find globs on alpine", async (t) => {
    stub.resolves({
      stdout: readFileSync(
        getLSOutputFixture("alpine-3.9.4-manifest-files.txt"),
      ).toString(),
    });

    const files = await docker.findGlobs([
      "**/package.json",
      "**/Gemfile.lock",
    ]);

    t.same(files, ["/app/Gemfile.lock", "/srv/app/package.json"]);
  });

  t.test("find a java manifest file on centos", async (t) => {
    stub.resolves({
      stdout: readFileSync(
        getLSOutputFixture("centos-7.6.1810-manifest-files.txt"),
      ).toString(),
    });

    const files = await docker.findGlobs(["**/pom.xml"]);

    t.same(files, ["/app/pom.xml"]);
  });

  t.test("find a node manifest file on debian", async (t) => {
    stub.resolves({
      stdout: readFileSync(
        getLSOutputFixture("debian-10.0-manifest-files.txt"),
      ).toString(),
    });

    const files = await docker.findGlobs(["**/package.json"]);

    t.same(files, ["/app/package.json"]);
  });

  t.test("finding no manifest files on ubuntu", async (t) => {
    stub.resolves({
      stdout: readFileSync(getLSOutputFixture("ubuntu-18.04.txt")).toString(),
    });

    const files = await docker.findGlobs([
      "**/package.json",
      "**/package-lock.json",
    ]);

    t.same(files, []);
  });

  test("getFileProduct", async (t) => {
    const execStub = sinon.stub(subProcess, "execute");

    // Stub Docker save file
    execStub
      .withArgs("docker", ["save", "-o", sinon.match.any, sinon.match.any])
      .callsFake(async (docker, [save, opt, file, image]) => {
        return {
          stdout: "",
          stderr: "",
        };
      });

    // Stub Docker cat file
    execStub
      .withArgs("docker", [
        "run",
        "--rm",
        "--entrypoint",
        '""',
        "--network",
        "none",
        sinon.match.any,
        "cat",
        sinon.match.any,
      ])
      .callsFake(
        async (
          docker,
          [run, rm, entry, empty, network, none, image, cat, file],
        ) => {
          if (file !== "/some/file") {
            throw { stderr: "file not found", stdout: "" };
          }
          return {
            stdout: "file content",
            stderr: "",
          };
        },
      );

    t.teardown(() => {
      execStub.restore();
    });

    t.test("file product, compatibility", async (t) => {
      const content = await docker.getTextFile("/some/file");
      t.equal(content, "file content");
    });

    t.test("file product with callback", async (t) => {
      const content = await docker.getActionProductByFileName(
        "/some/file",
        "md5",
        md5,
      );
      t.equal(content, "d10b4c3ff123b26dc068d43a8bef2d23");
    });
  });
});

test("getFileProducts", async (t) => {
  const examples = {
    "ubuntu:10.04": {
      dir: "ubuntu_10_04",
      expected: {
        txt: [
          ["/etc/debian_version", readOsFixtureFileIntoBuffer],
          ["/etc/lsb-release", readOsFixtureFileIntoBuffer],
          ["/var/lib/dpkg/status", readOsFixtureFileIntoBuffer],
        ],
        md5: [
          ["/etc/debian_version", readOsFixtureFileCalcMd5],
          ["/etc/lsb-release", readOsFixtureFileCalcMd5],
        ],
      },
    },
  };

  const txtPatterns = [
    ...aptAnalyzer.APT_PKGPATHS,
    ...apkAnalyzer.APK_PKGPATHS,
    ...osReleaseDetector.OS_VERPATHS,
  ];
  const md5Patterns = osReleaseDetector.OS_VERPATHS;

  const extractActions = [
    ...txtPatterns.map((p) => {
      return {
        name: "txt",
        pattern: p,
      };
    }),
    ...md5Patterns.map((p) => {
      return { name: "md5", pattern: p, callback: md5 };
    }),
  ];

  for (const targetImage of Object.keys(examples)) {
    await t.test(targetImage, async (t) => {
      const execStub = sinon.stub(subProcess, "execute");

      // Stub Docker save file
      execStub
        .withArgs("docker", ["save", "-o", sinon.match.any, sinon.match.any])
        .callsFake(async (docker, [save, opt, file, image]) => {
          try {
            const example = examples[image];

            const tarStream = fs.createWriteStream(file);
            tarStream.on("close", () => {
              return {
                stdout: "",
                stderr: "",
              };
            });

            const layerName: string = "0".repeat(64).concat("/layer.tar");
            const imagePack: PackStream = packStream();
            imagePack.entry(
              { name: layerName },
              await streamToBuffer(packFs(getOsFixturePath(example.dir, "fs"))),
            );
            imagePack.entry(
              { name: "manifest.json" },
              JSON.stringify([{ Layers: [layerName, undefined] }], (_, v) => {
                return v === undefined ? null : v;
              }),
            );

            imagePack.finalize();
            await imagePack.pipe(
              tarStream,
              { end: true },
            );
          } catch {
            // tslint:disable-next-line:no-string-throw
            throw {
              stderr: "",
              stdout: "",
            };
          }
        });

      // Stub Docker cat file
      execStub
        .withArgs("docker", [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          sinon.match.any,
          "cat",
          sinon.match.any,
        ])
        .callsFake(
          async (
            docker,
            [run, rm, entry, empty, network, none, image, cat, file],
          ) => {
            throw new Error("unexpected call to docker cat");
          },
        );

      // Stub Docker size
      execStub
        .withArgs("docker", [
          "inspect",
          sinon.match.any,
          "--format",
          "'{{.Size}}'",
        ])
        .callsFake(async (docker, [inspect, image, format, size]) => {
          return {
            stdout: "1", // minimal size, ensure static scan is used
            stderr: "",
          };
        });

      t.teardown(() => {
        execStub.restore();
      });

      const docker = new Docker(targetImage);

      await docker.extractAndCache(extractActions);

      const example = examples[targetImage];

      for (const extractActionName of Object.keys(example.expected)) {
        const contents = await docker.getActionProducts(extractActionName);
        // expected number of items
        t.equal(
          Object.keys(contents).length,
          example.expected[extractActionName].length,
        );
        for (const [expectedFilename, expectedProductFunction] of example
          .expected[extractActionName]) {
          // expected filename
          t.ok(
            Object.keys(contents).includes(expectedFilename),
            `exists ${expectedFilename} ${extractActionName}`,
          );
          // expected product
          t.ok(
            contents[expectedFilename].toString("utf8"),
            expectedProductFunction(example.dir, "fs", expectedFilename),
            `product ${expectedFilename} ${extractActionName}`,
          );
        }
      }
    });
  }
});
