import * as crypto from "crypto";
import { createReadStream, existsSync, unlinkSync } from "fs";
import * as os from "os";
import * as path from "path";
import { CmdOutput } from "../../lib/sub-process";
import * as subProcess from "../../lib/sub-process";

import { Docker } from "../../lib/docker";

describe("docker", () => {
  describe("save from docker daemon", () => {
    const TEST_TARGET_IMAGE = "hello-world:latest";
    const TEST_TARGET_IMAGE_DESTINATION = path.join(os.tmpdir(), "image.tar");

    const docker = new Docker();
    let expectedChecksum;

    beforeAll(async () => {
      const loadImage = path.join(
        __dirname,
        "../fixtures/docker-archives",
        "docker-save/hello-world.tar",
      );
      expectedChecksum = await getChecksum(loadImage);
      await subProcess.execute("docker", ["load", "--input", loadImage]);
    });

    afterEach(() => {
      if (existsSync(TEST_TARGET_IMAGE_DESTINATION)) {
        unlinkSync(TEST_TARGET_IMAGE_DESTINATION);
      }
    });

    test("image saved to specified location", async () => {
      const targetImage = TEST_TARGET_IMAGE;
      const targetImageDestination = TEST_TARGET_IMAGE_DESTINATION;

      await docker.save(targetImage, targetImageDestination);

      expect(existsSync(targetImageDestination)).toBeTruthy();
    });

    test("promise rejects when image doesn't exist", async () => {
      const image = "someImage:latest";
      const destination = "/tmp/image.tar";

      const result = docker.save(image, destination);

      //  rejects with expected error
      await expect(result).rejects.toThrowError();
      expect(existsSync(destination)).toBeFalsy();
    });

    test("promise rejects when image cannot be written to destination", async () => {
      const targetImage = TEST_TARGET_IMAGE;
      const targetImageDestination = "/somefolder/image.tar";

      const result = docker.save(targetImage, targetImageDestination);

      //  promise rejects with failed file open
      await expect(result).rejects.toThrowError(
        "ENOENT: no such file or directory, open '/somefolder/image.tar'",
      );
      expect(existsSync(targetImageDestination)).toBeFalsy();
    });

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
  });

  describe("pullCli", () => {
    const targetImage = "some:image";

    let subProcessExecuteStub: jest.SpyInstance<
      Promise<CmdOutput>,
      [command: string, args: string[], options?: any]
    >;
    let unit: Docker;

    beforeEach(async () => {
      const cmdOutputMock: CmdOutput = { stderr: "", stdout: "" };
      subProcessExecuteStub = jest
        .spyOn(subProcess, "execute")
        .mockImplementation(() => Promise.resolve(cmdOutputMock));

      unit = new Docker();
    });

    afterEach(() => {
      jest.resetAllMocks();
    });

    test("no args", async () => {
      await unit.pullCli(targetImage);
      const subProcessArgs = subProcessExecuteStub.mock.lastCall;

      //  args passed to subProcess.execute as expected
      expect(subProcessArgs).toEqual(["docker", ["pull", targetImage]]);
    });

    test("with args", async () => {
      await unit.pullCli(targetImage, { platform: "linux/arm64/v8" });
      const subProcessArgs = subProcessExecuteStub.mock.lastCall;

      //  args passed to subProcess.execute as expected
      expect(subProcessArgs).toEqual([
        "docker",
        ["pull", targetImage, "--platform=linux/arm64/v8"],
      ]);
    });
  });
});
