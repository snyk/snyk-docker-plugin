#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";
import { pack as packFs } from "tar-fs";
import { pack as packStream, Pack as PackStream } from "tar-stream";

import * as apkAnalyzer from "../../../lib/analyzer/apk-analyzer";
import * as aptAnalyzer from "../../../lib/analyzer/apt-analyzer";
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
      txt_length: 1,
      md5: { "etc/alpine-release": "a39b961d3a81ed894ae60fcd87534722" },
    },
    centos_6: {
      dir: "centos_6",
      txt_length: 0,
      md5: { "etc/redhat-release": "1ce68fef0638f1ea6de03c30694f2e6c" },
    },
    debian_9: {
      dir: "debian_9",
      txt_length: 2,
      md5: { "etc/os-release": "1a99d9f31f480f1077f996a761a0e6c0" },
    },
    ubuntu_10_04: {
      dir: "ubuntu_10_04",
      txt_length: 1,
      md5: {
        "etc/lsb-release": "a50b6779ddccab3277e2560028f3eb15",
        "etc/debian_version": "82711d8dc3e89c428b4694a284e32541",
      },
    },
  };

  const pkgPaths = [...aptAnalyzer.APT_PKGPATHS, ...apkAnalyzer.APK_PKGPATHS];

  const md5Paths = ["etc/*release", "etc/*version"];

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
        imagePack.pipe(
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

  t.teardown(() => {
    execStub.restore();
  });

  for (const targetImage of Object.keys(examples)) {
    await t.test(targetImage, async (t) => {
      const example = examples[targetImage];
      const docker = new Docker(targetImage);
      const result = await docker.extract(pkgPaths, md5Paths);
      t.same(Object.keys(result.txt).length, example.txt_length);
      t.same(Object.keys(result.md5).length, Object.keys(example.md5).length);
      for (const name of Object.keys(example.md5)) {
        t.same(result.md5[name], example.md5[name]);
      }
    });
  }
});
