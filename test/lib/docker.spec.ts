import * as crypto from "crypto";
import {
  createReadStream,
  createWriteStream,
  existsSync,
  mkdirSync,
  rmdirSync,
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
  describe("Pull from docker registry without docker binary", () => {
    test("Pass platform argument when pulling from registry", async () => {
      const docker = new Docker();
      const imagePath = path.join(__dirname, "save");
      await mkdirSync(imagePath, { recursive: true });
      const resp = await docker.pull(
        "registry-1.docker.io",
        "library/debian",
        "12.0",
        imagePath,
        "",
        "",
        "linux/386",
      );

      const tarPath = path.join(imagePath, "image.tar");

      expect(existsSync(tarPath)).toBeTruthy();
      const imageID = (
        await subProcess.execute("docker", ["load", "--input", tarPath])
      ).stdout
        .split("Loaded image ID: ")[1]
        .replace(/\n/g, "");
      const stdout = (await subProcess.execute("docker", ["inspect", imageID]))
        .stdout;
      expect(imageID).toEqual(
        "sha256:9743376b1f2144d61495397e2a7f044bbc25d61016cee4dbff8683d31eaed7fa",
      );
      const imageDetails = JSON.parse(stdout);
      const architecture = imageDetails[0].Architecture;
      expect(architecture).toEqual("386");
      unlinkSync(tarPath);
      rmdirSync(imagePath);
    });

    test("Pull arm64/v8 debian image from docker hub registry", async () => {
      const docker = new Docker();
      const imagePath = path.join(__dirname, "save");
      await mkdirSync(imagePath, { recursive: true });
      const resp = await docker.pull(
        "registry-1.docker.io",
        "library/debian",
        "12.0",
        imagePath,
        "",
        "",
        "linux/arm64/v8",
      );

      const tarPath = path.join(imagePath, "image.tar");

      expect(existsSync(tarPath)).toBeTruthy();
      const imageID = (
        await subProcess.execute("docker", ["load", "--input", tarPath])
      ).stdout
        .split("Loaded image ID: ")[1]
        .replace(/\n/g, "");
      const stdout = (await subProcess.execute("docker", ["inspect", imageID]))
        .stdout;
      expect(imageID).toEqual(
        "sha256:f800c324d2439563735dfc4de0da09a45b301687ded46936fcf2cf9256d4c6d3",
      );
      const imageDetails = JSON.parse(stdout);
      const architecture = imageDetails[0].Architecture;
      const variant = imageDetails[0].Variant;

      expect(architecture).toEqual("arm64");
      expect(variant).toEqual("v8");
      unlinkSync(tarPath);
      rmdirSync(imagePath);
    });

    test("Pull arm/v5 debian image from docker hub registry", async () => {
      const docker = new Docker();
      const imagePath = path.join(__dirname, "save");
      await mkdirSync(imagePath, { recursive: true });
      const resp = await docker.pull(
        "registry-1.docker.io",
        "library/debian",
        "12.0",
        imagePath,
        "",
        "",
        "linux/arm/v5",
      );

      const tarPath = path.join(imagePath, "image.tar");

      expect(existsSync(tarPath)).toBeTruthy();
      const imageID = (
        await subProcess.execute("docker", ["load", "--input", tarPath])
      ).stdout
        .split("Loaded image ID: ")[1]
        .replace(/\n/g, "");
      const stdout = (await subProcess.execute("docker", ["inspect", imageID]))
        .stdout;
      expect(imageID).toEqual(
        "sha256:bdbea07b48b33b5ffdd260fc11012b892651c4f0f84cc2b782103dd68989caa4",
      );
      const imageDetails = JSON.parse(stdout);
      const architecture = imageDetails[0].Architecture;
      const variant = imageDetails[0].Variant;

      expect(architecture).toEqual("arm");
      expect(variant).toEqual("v5");
      unlinkSync(tarPath);
      rmdirSync(imagePath);
    });
  });

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
