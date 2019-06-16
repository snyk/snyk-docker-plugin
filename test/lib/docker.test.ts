#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

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
    stub.callsFake(() => {
      // tslint:disable-next-line:no-string-throw
      throw { stderr: "cat: absent.txt: No such file or directory" };
    });
    const content = (await docker.catSafe("absent.txt")).stderr;
    t.equal(content, "", "empty string returned");
  });

  t.test("unexpected error", async (t) => {
    stub.callsFake(() => {
      // tslint:disable-next-line:no-string-throw
      throw { stderr: "something went horribly wrong", stdout: "" };
    });
    await t.rejects(
      docker.catSafe("absent.txt"),
      { stderr: "something went horribly wrong", stdout: "" },
      "rejects with expected error",
    );
  });
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

  const targetImage = "some:image";
  const docker = new Docker(targetImage);

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
