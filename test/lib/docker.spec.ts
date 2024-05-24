import * as crypto from "crypto";
import {
  createReadStream,
  createWriteStream,
  existsSync,
  unlinkSync,
} from "fs";
import * as os from "os";
import * as path from "path";
import * as tar from "tar-stream";
import * as tmp from "tmp";
import { Docker } from "../../lib/docker";
import { CmdOutput } from "../../lib/sub-process";
import * as subProcess from "../../lib/sub-process";

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
      const normalizedLoadImage = await normalizeImageTar(loadImage);
      expectedChecksum = await calculateImageSHA256(normalizedLoadImage);
      await subProcess.execute("docker", ["load", "--input", loadImage]);
    });

    afterEach(() => {
      if (existsSync(TEST_TARGET_IMAGE_DESTINATION)) {
        unlinkSync(TEST_TARGET_IMAGE_DESTINATION);
      }
    });

    async function calculateImageSHA256(tarFilePath: string): Promise<string> {
      return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = createReadStream(tarFilePath);

        stream.on("data", (data) => {
          hash.update(data);
        });

        stream.on("end", () => {
          resolve(hash.digest("hex"));
        });

        stream.on("error", (err) => {
          reject(err);
        });
      });
    }

    async function normalizeImageTar(tarFilePath: string): Promise<string> {
      return new Promise((resolve, reject) => {
        const extract = tar.extract();
        const pack = tar.pack();
        const tempFile = tmp.fileSync();
        const output = createWriteStream(tempFile.name);

        extract.on("entry", (header, stream, next) => {
          // Normalize the header
          header.mtime = new Date(0); // Set modification time to the epoch
          header.uid = 0; // Set user ID to 0
          header.gid = 0; // Set group ID to 0

          // Add entry to the new tar file
          const entry = pack.entry(header, next);
          stream.pipe(entry);
        });

        extract.on("finish", () => {
          pack.finalize();
        });

        output.on("finish", () => {
          resolve(tempFile.name);
        });

        extract.on("error", (err) => {
          reject(err);
        });

        pack.pipe(output);

        createReadStream(tarFilePath).pipe(extract);
      });
    }

    test("image saved to specified location", async () => {
      const targetImage = TEST_TARGET_IMAGE;
      const targetImageDestination = TEST_TARGET_IMAGE_DESTINATION;

      await docker.save(targetImage, targetImageDestination);

      expect(existsSync(targetImageDestination)).toBeTruthy();
      const normalizedTargetImage = await normalizeImageTar(
        targetImageDestination,
      );

      const checksum = await calculateImageSHA256(normalizedTargetImage);
      expect(checksum).toEqual(expectedChecksum);
    });

    test("promise rejects when image doesn't exist", async () => {
      const image = "someImage:latest";
      const destination = "/tmp/image.tar";

      const result = docker.save(image, destination);

      //  rejects with expected error
      await expect(result).rejects.toThrowError("server error");
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
