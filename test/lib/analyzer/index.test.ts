#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";
import { pack as packFs } from "tar-fs";
import { pack as packStream, Pack as PackStream } from "tar-stream";

import * as analyzer from "../../../lib/analyzer";
import * as imageInspector from "../../../lib/analyzer/image-inspector";
import { streamToBuffer } from "../../../lib/stream-utils";
import * as subProcess from "../../../lib/sub-process";

const getOsFixturePath = (...from) =>
  path.join(__dirname, "../../fixtures/os", ...from);

const readOsFixtureFile = (...from) =>
  fs.readFileSync(getOsFixturePath(...from), "utf8");

test("analyzer", async (t) => {
  const examples = {
    "alpine:2.6": {
      dir: "alpine_2_6_6",
    },
    "centos:6": {
      dir: "centos_6",
    },
    "debian:9.9": {
      dir: "debian_9",
    },
  };

  let staticScan: boolean;

  for (const targetImage of Object.keys(examples)) {
    await t.test(targetImage, async (t) => {
      const execStub = sinon.stub(subProcess, "execute");

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
            try {
              const example = examples[image];
              return {
                stdout: staticScan
                  ? ""
                  : readOsFixtureFile(example.dir, "fs", file),
                stderr: "",
              };
            } catch {
              // tslint:disable-next-line:no-string-throw
              throw {
                stderr: `cat: ${file}: No such file or directory`,
                stdout: "",
              };
            }
          },
        );

      // Stub Docker `run rpm` command
      execStub
        .withArgs("docker", [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          sinon.match.any,
          "rpm",
          "--nodigest",
          "--nosignature",
          "-qa",
          "--qf",
          '"%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SIZE}\n"',
        ])
        .callsFake(
          async (docker, [run, rm, entry, empty, network, none, image]) => {
            try {
              const example = examples[image];
              return {
                stdout: readOsFixtureFile(example.dir, "rpm-output.txt"),
                stderr: "",
              };
            } catch {
              // tslint:disable-next-line:no-string-throw
              throw {
                stderr: `docker: Error response from daemon: OCI runtime \
          create failed: container_linux.go:348: starting container process\
          caused "exec: \"rpm\": executable file not found in $PATH": unknown.`,
                stdout: "",
              };
            }
          },
        );

      // Stub Docker `node --version` command
      execStub
        .withArgs("docker", [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          sinon.match.any,
          "node",
          "--version",
        ])
        .callsFake(
          async (docker, [run, rm, entry, empty, network, none, image]) => {
            try {
              const example = examples[image];
              return {
                stdout: readOsFixtureFile(example.dir, "node-version.txt"),
                stderr: "",
              };
            } catch {
              // tslint:disable-next-line:no-string-throw
              throw {
                stderr: "docker: Error running `docker node --version`",
                stdout: "",
              };
            }
          },
        );

      // Stub Docker `java -version` command
      execStub
        .withArgs("docker", [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          sinon.match.any,
          "java",
          "-version",
        ])
        .callsFake(
          async (docker, [run, rm, entry, empty, network, none, image]) => {
            try {
              const example = examples[image];
              return readOsFixtureFile(example.dir, "openjdk-jre-version.txt");
            } catch {
              // tslint:disable-next-line:no-string-throw
              throw {
                stderr: "docker: Error running `docker java -version`",
                stdout: "",
              };
            }
          },
        );

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
            stdout: staticScan
              ? analyzer.STATIC_SCAN_MAX_IMAGE_SIZE
              : analyzer.STATIC_SCAN_MAX_IMAGE_SIZE + 1,
            stderr: "",
          };
        });

      const expectedId = "sha256:fake";
      const expectedLayers = ["sha256:fake1", "sha256:fake2", "sha256:fake3"];

      const stubbedData = {
        Id: expectedId,
        RootFS: {
          Layers: expectedLayers,
        },
        MoreStuff: "stuff",
      };
      const imageInspectorStub = sinon
        .stub(imageInspector, "detect")
        .resolves(stubbedData);

      t.teardown(() => {
        execStub.restore();
        imageInspectorStub.restore();
      });

      const example = examples[targetImage];
      const expectation = JSON.parse(
        readOsFixtureFile(example.dir, "analyzer-expect.json"),
      );

      staticScan = true;
      t.same(await analyzer.analyze(targetImage), expectation);

      staticScan = false;
      t.same(await analyzer.analyze(targetImage), expectation);
    });
  }
});
