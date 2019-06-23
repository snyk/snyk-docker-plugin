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

import * as apkAnalyzer from "../../../lib/analyzer/apk-analyzer";
import * as aptAnalyzer from "../../../lib/analyzer/apt-analyzer";
import { mapActionsToFiles } from "../../../lib/analyzer/image-extractor";
import * as osReleaseDetector from "../../../lib/analyzer/os-release-detector";
import { Docker } from "../../../lib/docker";
import { streamToBuffer } from "../../../lib/stream-utils";
import * as subProcess from "../../../lib/sub-process";

const getOsFixturePath = (...from) => {
  return path.join(__dirname, "../../fixtures/os", ...from);
};

test("static analyze", async (t) => {
  const examples = {
    "alpine:2.6": {
      dir: "alpine_2_6_6",
      txtCount: 1,
      md5: { "/etc/alpine-release": "a39b961d3a81ed894ae60fcd87534722" },
    },
    "centos:6": {
      dir: "centos_6",
      txtCount: 0,
      md5: { "/etc/redhat-release": "1ce68fef0638f1ea6de03c30694f2e6c" },
    },
    "debian:9.9": {
      dir: "debian_9",
      txtCount: 2,
      md5: { "/usr/lib/os-release": "1a99d9f31f480f1077f996a761a0e6c0" },
    },
    "ubuntu:10.04": {
      dir: "ubuntu_10_04",
      txtCount: 1,
      md5: {
        "/etc/lsb-release": "a50b6779ddccab3277e2560028f3eb15",
        "/etc/debian_version": "82711d8dc3e89c428b4694a284e32541",
      },
    },
  };

  const txtPatterns = [
    ...aptAnalyzer.APT_PKGPATHS,
    ...apkAnalyzer.APK_PKGPATHS,
    ...osReleaseDetector.OS_VERPATHS,
  ];
  const md5Patterns = osReleaseDetector.OS_VERPATHS;

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
            await imagePack.pipe(tarStream);
          } catch {
            // tslint:disable-next-line:no-string-throw
            throw {
              stderr: "",
              stdout: "",
            };
          }
        });

      t.teardown(() => {
        execStub.restore();
      });

      const example = examples[targetImage];
      const docker = new Docker(targetImage);

      const MD5 = "md5";

      const result = await docker.extract([
        ...mapActionsToFiles(txtPatterns, {
          name: "str",
          callback: (v) => v.toString("utf8"),
        }),
        ...mapActionsToFiles(md5Patterns, { name: MD5, callback: md5 }),
      ]);

      t.same(
        Object.keys(result).length,
        example.txtCount + Object.keys(example.md5).length,
      );
      for (const name of Object.keys(example.md5)) {
        t.same(result[name][MD5], example.md5[name]);
      }
    });
  }
});
