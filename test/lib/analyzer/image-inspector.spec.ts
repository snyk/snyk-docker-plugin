import * as fs from "fs";
import * as path from "path";
import * as tmp from "tmp";
import { v4 as uuidv4 } from "uuid";

import { DockerPullResult } from "@snyk/snyk-docker-pull";
import * as plugin from "../../../lib";
import * as imageInspector from "../../../lib/analyzer/image-inspector";
import { ArchiveResult } from "../../../lib/analyzer/types";
import { Docker } from "../../../lib/docker";
import * as subProcess from "../../../lib/sub-process";

function rmdirRecursive(customPath: string[]): void {
  if (customPath.length < 2) {
    return;
  }

  const joinedPath = path.join(...customPath);
  fs.rmdirSync(joinedPath, { recursive: true });
}

// prettier-ignore
describe("extractImageDetails", () => {
  it.each`
  
    image | expected
    
    ${"hello-world"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "library/hello-world",
      tag: "latest",
    }}
    ${"gcr.io/kubernetes/someImage:alpine"} | ${{
      hostname: "gcr.io",
      imageName: "kubernetes/someImage",
      tag: "alpine",
    }}
    ${"nginx:1.18"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "library/nginx",
      tag: "1.18",
    }}
    ${"nginx:1.18"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "library/nginx",
      tag: "1.18",
    }}
    ${"calico/cni:release-v3.14"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "calico/cni",
      tag: "release-v3.14",
    }}
    ${"gcr.io:3000/kubernetes/someImage:alpine"} | ${{
      hostname: "gcr.io:3000",
      imageName: "kubernetes/someImage",
      tag: "alpine",
    }}
    ${"localhost/alpine"} | ${{
      hostname: "localhost",
      imageName: "alpine",
      tag: "latest",
    }}
    ${"localhost:1337/kubernetes/someImage:alpine"} | ${{
      hostname: "localhost:1337",
      imageName: "kubernetes/someImage",
      tag: "alpine",
    }}
    ${"gcr.io/distroless/base-debian10@sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf"} | ${{
      hostname: "gcr.io",
      imageName: "distroless/base-debian10",
      tag: "sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf",
    }}
    ${"localhost:1234/foo/bar@sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf"} | ${{
      hostname: "localhost:1234",
      imageName: "foo/bar",
      tag: "sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf",
    }}
  `("extract details for $image", ({ image, expected }) => {
    const {
      hostname,
      imageName,
      tag,
    } = imageInspector.extractImageDetails(image);
    expect(hostname).toEqual(expected.hostname);
    expect(imageName).toEqual(expected.imageName);
    expect(tag).toEqual(expected.tag);
  });
  it("should throw an error if the image name has an invalid format", async () => {
     const imageNameAndTag = "/test:unknown";

     await expect(() =>
       plugin.scan({
         path: imageNameAndTag,
       }),
     ).rejects.toEqual(
       new Error("invalid image format"),
     );
   });
});

describe("getImageArchive", () => {
  const targetImage = "library/hello-world:latest";

  describe("from the local daemon if it exists", () => {
    const customPath = "./other_custom/image/save/path/local/daemon";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");
      const loadImage = path.join(
        __dirname,
        "../../fixtures/docker-archives",
        "docker-save/hello-world.tar",
      );
      await subProcess.execute("docker", ["load", "--input", loadImage]);
      const archiveLocation = await imageInspector.getImageArchive(
        targetImage,
        imageSavePath,
      );

      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      expect(dockerPullSpy).not.toHaveBeenCalled();

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);

      const customPathExistsOnDisk: boolean = fs.existsSync(customPath);
      expect(customPathExistsOnDisk).toBe(true);
    });
  });

  describe("from remote registry with binary", () => {
    it("should produce the expected state", async () => {
      const customPath = tmp.dirSync().name;
      const imageSavePath = path.join(customPath, uuidv4());
      const registryPullSpy = jest.spyOn(Docker.prototype, "pull");

      const archiveLocation: ArchiveResult =
        await imageInspector.getImageArchive(targetImage, imageSavePath);

      expect(registryPullSpy).not.toHaveBeenCalled();
      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);

      const customPathExistsOnDisk: boolean = fs.existsSync(customPath);
      expect(customPathExistsOnDisk).toBe(true);

      await subProcess.execute("docker", ["image", "rm", targetImage]);
    });

    it("should fail correctly when manifest is not found for given tag", async () => {
      const customPath = tmp.dirSync().name;
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullCliSpy = jest
        .spyOn(Docker.prototype, "pullCli")
        .mockImplementation(() => {
          return new Promise<subProcess.CmdOutput>((_, reject) => {
            reject({
              stdout: "",
              stderr:
                '"Error response from daemon: manifest for library/hello-world:non-existent-tag not found: manifest unknown: manifest unknown\n"',
            });
          });
        });
      const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");

      await expect(
        imageInspector.getImageArchive(
          "library/hello-world:non-existent-tag",
          imageSavePath,
        ),
      ).rejects.toEqual(
        new Error("The image does not exist for the current platform"),
      );

      expect(dockerPullCliSpy).toHaveBeenCalled();
      expect(dockerPullSpy).not.toHaveBeenCalled();
    });
  });

  describe("from remote registry with no platform feature binary", () => {
    const customPath = "./new_custom/image/save/path";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      // we simulate the Docker CLI being so old that the `--platform` flag is not supported at all.
      const dockerPullCliSpy = jest
        .spyOn(Docker.prototype, "pullCli")
        .mockImplementation(() => {
          return new Promise<subProcess.CmdOutput>((_, reject) => {
            reject({
              stdout: "",
              stderr: "unknown flag: --platform\nSee 'docker pull --help'.",
            });
          });
        });

      await expect(
        imageInspector.getImageArchive(targetImage, imageSavePath),
      ).rejects.toEqual(
        new Error(
          '"--platform" is only supported on a Docker daemon with version later than 17.09',
        ),
      );

      expect(dockerPullCliSpy).toHaveBeenCalled();

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(false);
    });
  });

  describe("from remote registry with experimental platform feature binary", () => {
    const customPath = "./new_custom/image/save/path";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullCliSpy = jest
        .spyOn(Docker.prototype, "pullCli")
        .mockImplementation(() => {
          return new Promise<subProcess.CmdOutput>((_, reject) => {
            reject({
              stdout: "",
              stderr:
                '"--platform" is only supported on a Docker daemon with experimental features enabled',
            });
          });
        });

      await expect(
        imageInspector.getImageArchive(targetImage, imageSavePath),
      ).rejects.toEqual(
        new Error(
          '"--platform" is only supported on a Docker daemon with experimental features enabled',
        ),
      );

      expect(dockerPullCliSpy).toHaveBeenCalled();

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(false);
    });
  });

  describe("from remote registry without binary", () => {
    const customPath = "./new_custom/image/save/path";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");
      jest.spyOn(subProcess, "execute").mockImplementation(() => {
        throw new Error();
      });

      const archiveLocation = await imageInspector.getImageArchive(
        targetImage,
        imageSavePath,
      );

      expect(dockerPullSpy).toHaveBeenCalled();
      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);
    });
  });

  describe("from remote registry with authentication", () => {
    const customPath = "./my_custom/image/save/path/auth";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullSpy = jest
        .spyOn(Docker.prototype, "pull")
        .mockImplementation((_1, _2, _3, imageSavePath) => {
          fs.writeFileSync(path.join(imageSavePath, "image.tar"), "");
          return Promise.resolve({} as DockerPullResult);
        });
      jest.spyOn(subProcess, "execute").mockImplementation(() => {
        throw new Error();
      });

      const username = "someUsername";
      const password = "somePassword";

      const archiveLocation = await imageInspector.getImageArchive(
        targetImage!,
        imageSavePath,
        username,
        password,
      );

      expect(dockerPullSpy).toHaveBeenCalledWith(
        "registry-1.docker.io",
        "library/hello-world",
        "latest",
        imageSavePath,
        username,
        password,
      );
      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      // Checking the image file exists is not done to test that the mockImplementation worked,
      // but instead asserts the preconditions for removeArchive() to actually work - i.e.
      // `expect(imageExistsOnDiskAfterDelete).toBe(false);` gives us no useful assurances
      // if the image wasn't there to begin with
      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);

      const tmpFolderExistsOnDisk: boolean = fs.existsSync(imageSavePath);
      expect(tmpFolderExistsOnDisk).toBe(false);

      const customPathExistsOnDisk: boolean = fs.existsSync(customPath);
      expect(customPathExistsOnDisk).toBe(true);
    });
  });
});
