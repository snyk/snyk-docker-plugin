import * as crypto from "crypto";
import { createReadStream, existsSync, unlinkSync } from "fs";
import * as os from "os";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";
import * as subProcess from "../../lib/sub-process";

import { Docker } from "../../lib/docker";

function getChecksum(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const file = createReadStream(path);

    file.on("error", (err) => {
      reject(err);
    });

    file.on("data", (chunk) => {
      hash.update(chunk);
    });

    file.on("close", () => {
      resolve(hash.digest("hex"));
    });
  });
}

test("save from docker daemon", async (t) => {
  const targetImage = "hello-world:latest";
  const docker = new Docker();
  let expectedChecksum: string;

  await t.test("prerequisites for next tests", async () => {
    const loadImage = path.join(
      __dirname,
      "../fixtures/docker-archives",
      "docker-save/hello-world.tar",
    );
    expectedChecksum = await getChecksum(loadImage);
    await subProcess.execute("docker", ["load", "--input", loadImage]);
  });

  await t.test("image saved to specified location", async (t) => {
    const destination = path.join(os.tmpdir(), "image.tar");

    t.tearDown(() => {
      if (existsSync(destination)) {
        unlinkSync(destination);
      }
    });

    await docker.save(targetImage, destination);
    t.true(existsSync(destination));
    const checksum = await getChecksum(destination);
    t.equal(
      checksum,
      expectedChecksum,
      "exported tar checksum matched expected",
    );
  });

  await t.test("promise rejects when image doesn't exist", async (t) => {
    const image = "someImage:latest";
    await t.rejects(
      docker.save(image, "/tmp/image.tar"),
      "server error",
      "rejects with expected error",
    );
    t.false(existsSync("/tmp/image.tar"));
  });

  await t.test(
    "promise rejects when image cannot be written to destination",
    async (t) => {
      const destination = "/somefolder/image.tar";
      await t.rejects(
        docker.save(targetImage, destination),
        { code: "ENOENT" },
        "promise rejects with failed file open",
      );
      t.false(existsSync(destination));
    },
  );
});

test("pullCli", async (t) => {
  const stub = sinon.stub(subProcess, "execute").resolves();
  t.beforeEach(async () => {
    stub.resetHistory();
  });
  t.tearDown(() => {
    stub.restore();
  });

  const targetImage = "some:image";
  const docker = new Docker();

  t.test("no args", async (t) => {
    await docker.pullCli(targetImage);
    const subProcessArgs = stub.getCall(0).args;
    t.same(
      subProcessArgs,
      ["docker", ["pull", targetImage]],
      "args passed to subProcess.execute as expected",
    );
  });

  t.test("with args", async (t) => {
    await docker.pullCli(targetImage, { platform: "linux/arm64/v8" });
    const subProcessArgs = stub.getCall(0).args;
    t.same(
      subProcessArgs,
      ["docker", ["pull", targetImage, "--platform=linux/arm64/v8"]],
      "args passed to subProcess.execute as expected",
    );
  });
});
