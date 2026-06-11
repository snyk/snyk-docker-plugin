import {
  createReadStream,
  existsSync,
  mkdirSync,
  rmdirSync,
  unlinkSync,
} from "fs";
import * as os from "os";
import * as path from "path";
import * as tar from "tar-stream";
import { Docker } from "../../lib/docker";
import { CmdOutput } from "../../lib/sub-process";
import * as subProcess from "../../lib/sub-process";

describe("docker", () => {
  describe("Pull from docker registry without docker binary", () => {
    test("Pass platform argument when pulling from registry", async () => {
      const docker = new Docker();
      const imagePath = path.join(__dirname, "save");
      await mkdirSync(imagePath, { recursive: true });
      await docker.pull(
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
      await docker.pull(
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
      await docker.pull(
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
    let expectedManifest: ImageManifest;

    beforeAll(async () => {
      const loadImage = path.join(
        __dirname,
        "../fixtures/docker-archives",
        "docker-save/hello-world.tar",
      );
      expectedManifest = await readImageManifest(loadImage);
      await subProcess.execute("docker", ["load", "--input", loadImage]);
    });

    afterEach(() => {
      if (existsSync(TEST_TARGET_IMAGE_DESTINATION)) {
        unlinkSync(TEST_TARGET_IMAGE_DESTINATION);
      }
    });

    interface ImageManifest {
      Config: string;
      Layers: string[];
    }

    async function readImageManifest(
      tarFilePath: string,
    ): Promise<ImageManifest> {
      return new Promise((resolve, reject) => {
        const extract = tar.extract();
        let manifest: ImageManifest | undefined;

        extract.on("entry", (header, stream, next) => {
          if (header.name === "manifest.json") {
            const chunks: Buffer[] = [];
            stream.on("data", (chunk) => chunks.push(chunk));
            stream.on("end", () => {
              manifest = JSON.parse(Buffer.concat(chunks).toString("utf8"))[0];
              next();
            });
          } else {
            stream.on("end", next);
            stream.resume();
          }
        });

        extract.on("finish", () => {
          if (manifest) {
            resolve(manifest);
          } else {
            reject(new Error(`manifest.json not found in ${tarFilePath}`));
          }
        });

        extract.on("error", (err) => {
          reject(err);
        });

        createReadStream(tarFilePath).pipe(extract);
      });
    }

    test("image saved to specified location", async () => {
      const targetImage = TEST_TARGET_IMAGE;
      const targetImageDestination = TEST_TARGET_IMAGE_DESTINATION;

      await docker.save(targetImage, targetImageDestination);

      expect(existsSync(targetImageDestination)).toBeTruthy();

      // Compare the manifest's config and layer digests rather than archive
      // bytes: docker save output is not byte-stable across engine versions
      // (e.g. Docker 29 omits the empty OnBuild field from the legacy config
      // blob, which changes the whole-archive checksum).
      const savedManifest = await readImageManifest(targetImageDestination);
      expect(savedManifest.Config).toEqual(expectedManifest.Config);
      expect(savedManifest.Layers).toEqual(expectedManifest.Layers);
    });

    test("promise rejects when image doesn't exist", async () => {
      const image = "image-that-does-not-exist:latest";
      const destination = "/tmp/image.tar";

      const result = docker.save(image, destination);

      // The daemon responds 404, which Docker.save surfaces as "not found".
      // (An invalid reference like "someImage" is no longer usable here:
      // Docker 29 rejects it with 400 before checking existence, where
      // older engines returned 500.)
      await expect(result).rejects.toThrowError("not found");
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
