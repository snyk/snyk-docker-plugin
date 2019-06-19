#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as md5 from "md5";
import * as sinon from "sinon";
import { test } from "tap";
import * as subProcess from "../../lib/sub-process";

import { Docker } from "../../lib/docker";

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

test("getFile", async (t) => {
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

  t.test("file content", async (t) => {
    const content = await docker.getFile("/some/file");
    t.equal(content, "file content");
  });

  t.test("file content with callback", async (t) => {
    const content = await docker.getFile("/some/file", {
      name: "md5",
      call: md5,
    });
    t.equal(content, "d10b4c3ff123b26dc068d43a8bef2d23");
  });
});
