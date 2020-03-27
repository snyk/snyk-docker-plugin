#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { readFileSync } from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";
import * as subProcess from "../../lib/sub-process";

import { Docker } from "../../lib/docker";

const jarGlobs = ["**/*.jar"];

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

  t.test("directory found, some files inaccessable", async (t) => {
    const lsResult = ".\n..\n.dockerenv\nbin/\ndev/\netc/\nusr/\nvar/\n";
    const lsErrors = "ls: can't open '/root': Permission denied";
    stub.callsFake(() => {
      throw { stdout: lsResult, stderr: lsErrors };
    });

    const result = await docker.lsSafe("/abc");
    t.equal(result.stdout, lsResult, "results returned");
    t.equal(result.stderr, lsErrors, "errors also returned");
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
      stdout:
        "./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\nfile2.txt\njar1.jar\njar2.jar",
    });
    const { manifestFiles, binaryFiles } = await docker.findGlobs(
      { manifestGlobs: ["**/file?.*"], binaryGlobs: jarGlobs },
      [],
      "/",
      false,
    );
    t.same(manifestFiles, ["/file1.txt", "/file2.txt"]);
    t.same(binaryFiles, ["/jar1.jar", "/jar2.jar"]);
  });

  t.test("find globs in a directory structure", async (t) => {
    stub.resolves({
      stdout:
        "/app:\n./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\nfile2.txt\n\n/app/dir1:" +
        "\n./\n../\ndir11/\nfile3.json\nfile4.txt\njar1.jar\n/app/dir1/dir11:\n./\n../\n" +
        "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.json\n",
    });
    const { manifestFiles, binaryFiles } = await docker.findGlobs(
      { manifestGlobs: ["**/file?.json"], binaryGlobs: jarGlobs },
      [],
      "/foo",
    );
    t.same(manifestFiles, ["/dir1/file3.json", "/dir3/file6.json"]);
    t.same(binaryFiles, ["/dir1/jar1.jar"]);
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
        "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.csproj\njar1.jar\n",
    });
    const { manifestFiles, binaryFiles } = await docker.findGlobs(
      { manifestGlobs: registryGlobs, binaryGlobs: jarGlobs },
      [],
      "/foo",
    );
    t.same(manifestFiles, [
      "/pom.xml",
      "/dir1/package.json",
      "/dir1/package-lock.json",
      "/dir3/file6.csproj",
    ]);
    t.same(binaryFiles, ["/dir3/jar1.jar"]);
  });

  t.test("find globs using registry globs with exclude globs", async (t) => {
    stub.resolves({
      stdout:
        "/app:\n./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\npom.xml\n\n/app/dir1:" +
        "\n./\n../\ndir11/\npackage.json\npackage-lock.json\n\n/app/dir1/dir11:\n./\n../\n" +
        "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.csproj\n",
    });
    const { manifestFiles, binaryFiles } = await docker.findGlobs(
      { manifestGlobs: registryGlobs, binaryGlobs: jarGlobs },
      ["/dir1/*"],
      "/foo",
    );
    t.same(manifestFiles, ["/pom.xml", "/dir3/file6.csproj"]);
    t.same(binaryFiles, []);
  });

  t.test(
    "find globs on ghost app using node_modules exclude glob",
    async (t) => {
      stub.resolves({
        stdout: readFileSync(getLSOutputFixture("ghost-app.txt")).toString(),
      });

      const { manifestFiles } = await docker.findGlobs(
        {
          manifestGlobs: [
            "**/package.json",
            "**/package-lock.json",
            "**/yarn.lock",
          ],
          binaryGlobs: [],
        },
        ["**/node_modules/**"],
        "/foo",
      );

      t.same(manifestFiles, [
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

    const { manifestFiles } = await docker.findGlobs(
      {
        manifestGlobs: ["**/package.json", "**/Gemfile.lock"],
        binaryGlobs: [],
      },
      [],
      "/foo",
    );

    t.same(manifestFiles, ["/app/Gemfile.lock", "/srv/app/package.json"]);
  });

  t.test("find a java manifest file on centos", async (t) => {
    stub.resolves({
      stdout: readFileSync(
        getLSOutputFixture("centos-7.6.1810-manifest-files.txt"),
      ).toString(),
    });

    const { manifestFiles } = await docker.findGlobs(
      { manifestGlobs: ["**/pom.xml"], binaryGlobs: [] },
      [],
      "/foo",
    );

    t.same(manifestFiles, ["/app/pom.xml"]);
  });

  t.test("find a node manifest file on debian", async (t) => {
    stub.resolves({
      stdout: readFileSync(
        getLSOutputFixture("debian-10.0-manifest-files.txt"),
      ).toString(),
    });

    const { manifestFiles } = await docker.findGlobs(
      { manifestGlobs: ["**/package.json"], binaryGlobs: [] },
      [],
      "/foo",
    );

    t.same(manifestFiles, ["/app/package.json"]);
  });

  t.test("finding no manifest files on ubuntu", async (t) => {
    stub.resolves({
      stdout: readFileSync(getLSOutputFixture("ubuntu-18.04.txt")).toString(),
    });

    const { manifestFiles } = await docker.findGlobs(
      {
        manifestGlobs: ["**/package.json", "**/package-lock.json"],
        binaryGlobs: [],
      },
      [],
      "/foo",
    );

    t.same(manifestFiles, []);
  });

  // Test special case when scanning from the root

  t.test("find from root directory structure", async (t) => {
    stub.onCall(0).resolves({
      stdout: "./\n../\n.dockerenv\napp/\nlib/\ndev/\nsys/\n",
    });
    stub.onCall(1).resolves({
      stdout: "/app:\n./\n../\ncomposer.json\ncomposer.lock\n",
    });
    stub.onCall(2).resolves({
      stdout:
        "/lib:\n./\n../\napk/\nfirmware/\nld-musl-x86_64.so.1\n" +
        "libc.musl-x86_64.so.1\nlibcrypto.so.1.1\nlibssl.so.1.1\n" +
        "libz.so.1\nlibz.so.1.2.11\nmdev/\n\n/lib/apk:\n./\n../\n" +
        "db/\n\n/lib/apk/db:\n./\n../\ninstalled\nlock\nscripts.tar\n" +
        "triggers\n\n/lib/firmware:\n./\n../\n\n/lib/mdev:\n./\n../\n",
    });
    stub.onCall(3).resolves({
      stdout: "/dev:\n./\n../\ndev1\ndev2\n",
    });
    stub.onCall(4).resolves({
      stdout: "/sys:\n./\n../\nsys1\nsys2\n",
    });

    const { manifestFiles } = await docker.findGlobs({
      manifestGlobs: ["**/*"],
      binaryGlobs: [],
    });
    t.same(manifestFiles, [
      "/app/composer.json",
      "/app/composer.lock",
      "/lib/ld-musl-x86_64.so.1",
      "/lib/libc.musl-x86_64.so.1",
      "/lib/libcrypto.so.1.1",
      "/lib/libssl.so.1.1",
      "/lib/libz.so.1",
      "/lib/libz.so.1.2.11",
      "/lib/apk/db/installed",
      "/lib/apk/db/lock",
      "/lib/apk/db/scripts.tar",
      "/lib/apk/db/triggers",
    ]);

    t.true(
      stub.calledThrice,
      "Check that calls for dev and sys did not happen",
    );
  });

  t.test(
    "find from root directory structure with system directories",
    async (t) => {
      stub.onCall(0).resolves({
        stdout: "./\n../\n.dockerenv\napp/\nlib/\ndev/\nsys/\n",
      });
      stub.onCall(1).resolves({
        stdout: "/app:\n./\n../\ncomposer.json\ncomposer.lock\n",
      });
      stub.onCall(2).resolves({
        stdout:
          "/lib:\n./\n../\napk/\nfirmware/\nld-musl-x86_64.so.1\n" +
          "libc.musl-x86_64.so.1\nlibcrypto.so.1.1\nlibssl.so.1.1\n" +
          "libz.so.1\nlibz.so.1.2.11\nmdev/\n\n/lib/apk:\n./\n../\n" +
          "db/\n\n/lib/apk/db:\n./\n../\ninstalled\nlock\nscripts.tar\n" +
          "triggers\n\n/lib/firmware:\n./\n../\n\n/lib/mdev:\n./\n../\n",
      });
      stub.onCall(3).resolves({
        stdout: "/dev:\n./\n../\ndev1\ndev2\n",
      });
      stub.onCall(4).resolves({
        stdout: "/sys:\n./\n../\nsys1\nsys2\n",
      });

      const { manifestFiles } = await docker.findGlobs(
        { manifestGlobs: ["**/*"], binaryGlobs: [] },
        [],
        "/",
        true,
        [],
      );
      t.same(manifestFiles, [
        "/app/composer.json",
        "/app/composer.lock",
        "/lib/ld-musl-x86_64.so.1",
        "/lib/libc.musl-x86_64.so.1",
        "/lib/libcrypto.so.1.1",
        "/lib/libssl.so.1.1",
        "/lib/libz.so.1",
        "/lib/libz.so.1.2.11",
        "/lib/apk/db/installed",
        "/lib/apk/db/lock",
        "/lib/apk/db/scripts.tar",
        "/lib/apk/db/triggers",
        "/dev/dev1",
        "/dev/dev2",
        "/sys/sys1",
        "/sys/sys2",
      ]);

      t.same(stub.callCount, 5, "Check that all calls did happen");
    },
  );
});
